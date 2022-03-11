//===-- TraceRecorder.cpp - race detector -------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder, a race detector.
//
// The tool is under development, for the details about previous versions see
// http://code.google.com/p/data-race-test
//
// The instrumentation phase is quite simple:
//   - Insert calls to run-time library before every memory access.
//      - Optimizations may apply to avoid instrumenting some of the accesses.
//   - Insert calls at function entry/exit.
// The rest is handled by the run-time library.
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/TraceRecorder.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/InitializePasses.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

#define DEBUG_TYPE "trec"

static cl::opt<bool> ClInstrumentMemoryAccesses(
    "trec-instrument-memory-accesses", cl::init(true),
    cl::desc("Instrument memory accesses"), cl::Hidden);
static cl::opt<bool>
    ClInstrumentFuncEntryExit("trec-instrument-func-entry-exit", cl::init(true),
                              cl::desc("Instrument function entry and exit"),
                              cl::Hidden);
static cl::opt<bool> ClHandleCxxExceptions(
    "trec-handle-cxx-exceptions", cl::init(true),
    cl::desc("Handle C++ exceptions (insert cleanup blocks for unwinding)"),
    cl::Hidden);
static cl::opt<bool> ClInstrumentAtomics("trec-instrument-atomics",
                                         cl::init(true),
                                         cl::desc("Instrument atomics"),
                                         cl::Hidden);
static cl::opt<bool> ClInstrumentMemIntrinsics(
    "trec-instrument-memintrinsics", cl::init(false),
    cl::desc("Instrument memintrinsics (memset/memcpy/memmove)"), cl::Hidden);
static cl::opt<bool> ClInstrumentBranch(
    "trec-instrument-branch", cl::init(true),
    cl::desc("Instrument branch points (indirectcalls/invoke calls/conditional "
             "branches/switches)"),
    cl::Hidden);
static cl::opt<bool>
    ClInstrumentFuncParam("trec-instrument-function-parameters", cl::init(true),
                          cl::desc("Instrument function parameters"),
                          cl::Hidden);

STATISTIC(NumInstrumentedReads, "Number of instrumented reads");
STATISTIC(NumInstrumentedWrites, "Number of instrumented writes");
STATISTIC(NumOmittedReadsBeforeWrite,
          "Number of reads ignored due to following writes");
STATISTIC(NumAccessesWithBadSize, "Number of accesses with bad size");
STATISTIC(NumInstrumentedVtableWrites, "Number of vtable ptr writes");
STATISTIC(NumInstrumentedVtableReads, "Number of vtable ptr reads");
STATISTIC(NumOmittedReadsFromConstantGlobals,
          "Number of reads from constant globals");
STATISTIC(NumOmittedReadsFromVtable, "Number of vtable reads");
STATISTIC(NumOmittedNonCaptured, "Number of accesses ignored due to capturing");

const char kTrecModuleCtorName[] = "trec.module_ctor";
const char kTrecInitName[] = "__trec_init";

namespace {

/// TraceRecorder: instrument the code in module to record traces.
///
/// Instantiating TraceRecorder inserts the trec runtime library API
/// function declarations into the module if they don't exist already.
/// Instantiating ensures the __trec_init function is in the list of global
/// constructors for the module.
struct TraceRecorder {
  TraceRecorder() {
    // Sanity check options and warn user.
  }

  bool sanitizeFunction(Function &F, const TargetLibraryInfo &TLI);

private:
  SmallDenseMap<Instruction *, unsigned int> FuncCallOrders;
  unsigned int FuncCallOrderCounter;

  // Internal Instruction wrapper that contains more information about the
  // Instruction from prior analysis.
  struct InstructionInfo {
    // Instrumentation emitted for this instruction is for a compounded set of
    // read and write operations in the same basic block.
    static constexpr unsigned kCompoundRW = (1U << 0);

    explicit InstructionInfo(Instruction *Inst) : Inst(Inst) {}

    Instruction *Inst;
    unsigned Flags = 0;
  };

  void initialize(Module &M);
  bool instrumentLoadOrStore(const InstructionInfo &II, const DataLayout &DL);
  bool instrumentAtomic(Instruction *I, const DataLayout &DL);
  bool instrumentBranch(Instruction *I, const DataLayout &DL);
  bool instrumentMemIntrinsic(Instruction *I);
  bool instrumentFunctionReturn(Instruction *I);
  bool instrumentFunctionParamCall(Instruction *I);
  bool instrumentFunctionCall(Instruction *I);
  int getMemoryAccessFuncIndex(Value *Addr, const DataLayout &DL);
  struct ValSourceInfo {
    Value *Addr; // null if not found in variables
    uint8_t Idx; // index in function call parameters, start from 1. null if not
                 // found in parameters
  };
  void getSource(Value *Val, Function *F, ValSourceInfo &VSI);

  Type *IntptrTy;
  FunctionCallee TrecFuncEntry;
  FunctionCallee TrecFuncExit;
  FunctionCallee TrecIgnoreBegin;
  FunctionCallee TrecIgnoreEnd;
  // Accesses sizes are powers of two: 1, 2, 4, 8, 16.
  static const size_t kNumberOfAccessSizes = 5;
  FunctionCallee TrecRead[kNumberOfAccessSizes];
  FunctionCallee TrecWrite[kNumberOfAccessSizes];
  FunctionCallee TrecUnalignedRead[kNumberOfAccessSizes];
  FunctionCallee TrecUnalignedWrite[kNumberOfAccessSizes];
  FunctionCallee TrecCompoundRW[kNumberOfAccessSizes];
  FunctionCallee TrecUnalignedCompoundRW[kNumberOfAccessSizes];
  FunctionCallee TrecAtomicLoad[kNumberOfAccessSizes];
  FunctionCallee TrecAtomicStore[kNumberOfAccessSizes];
  FunctionCallee TrecAtomicRMW[AtomicRMWInst::LAST_BINOP + 1]
                              [kNumberOfAccessSizes];
  FunctionCallee TrecAtomicCAS[kNumberOfAccessSizes];
  FunctionCallee TrecAtomicThreadFence;
  FunctionCallee TrecAtomicSignalFence;
  FunctionCallee MemmoveFn, MemcpyFn, MemsetFn;
  FunctionCallee TrecBranch;
  FunctionCallee TrecFuncParam;
  FunctionCallee TrecFuncEnterOrder;
  FunctionCallee TrecFuncExitParam;
};

struct TraceRecorderLegacyPass : FunctionPass {
  TraceRecorderLegacyPass() : FunctionPass(ID) {
    initializeTraceRecorderLegacyPassPass(*PassRegistry::getPassRegistry());
  }
  StringRef getPassName() const override;
  void getAnalysisUsage(AnalysisUsage &AU) const override;
  bool runOnFunction(Function &F) override;
  bool doInitialization(Module &M) override;
  static char ID; // Pass identification, replacement for typeid.
private:
  Optional<TraceRecorder> TRec;
};

void insertModuleCtor(Module &M) {
  getOrCreateSanitizerCtorAndInitFunctions(
      M, kTrecModuleCtorName, kTrecInitName, /*InitArgTypes=*/{},
      /*InitArgs=*/{},
      // This callback is invoked when the functions are created the first
      // time. Hook them into the global ctors list in that case:
      [&](Function *Ctor, FunctionCallee) { appendToGlobalCtors(M, Ctor, 0); });
}

} // namespace

PreservedAnalyses TraceRecorderPass::run(Function &F,
                                         FunctionAnalysisManager &FAM) {
  TraceRecorder TRec;
  if (TRec.sanitizeFunction(F, FAM.getResult<TargetLibraryAnalysis>(F)))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

PreservedAnalyses TraceRecorderPass::run(Module &M,
                                         ModuleAnalysisManager &MAM) {
  insertModuleCtor(M);
  return PreservedAnalyses::none();
}

char TraceRecorderLegacyPass::ID = 0;
INITIALIZE_PASS_BEGIN(TraceRecorderLegacyPass, "trec",
                      "TraceRecorder: record trace.", false, false)
INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfoWrapperPass)
INITIALIZE_PASS_END(TraceRecorderLegacyPass, "trec",
                    "TraceRecorder: record trace.", false, false)

StringRef TraceRecorderLegacyPass::getPassName() const {
  return "TraceRecorderLegacyPass";
}

void TraceRecorderLegacyPass::getAnalysisUsage(AnalysisUsage &AU) const {
  AU.addRequired<TargetLibraryInfoWrapperPass>();
}

bool TraceRecorderLegacyPass::doInitialization(Module &M) {
  insertModuleCtor(M);
  TRec.emplace();
  return true;
}

bool TraceRecorderLegacyPass::runOnFunction(Function &F) {
  auto &TLI = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI(F);
  TRec->sanitizeFunction(F, TLI);
  return true;
}

FunctionPass *llvm::createTraceRecorderLegacyPassPass() {
  return new TraceRecorderLegacyPass();
}

void TraceRecorder::initialize(Module &M) {
  const DataLayout &DL = M.getDataLayout();
  IntptrTy = DL.getIntPtrType(M.getContext());

  IRBuilder<> IRB(M.getContext());
  AttributeList Attr;
  Attr = Attr.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
  // Initialize the callbacks.
  TrecFuncEntry = M.getOrInsertFunction("__trec_func_entry", Attr,
                                        IRB.getVoidTy(), IRB.getInt8PtrTy());
  TrecFuncExit =
      M.getOrInsertFunction("__trec_func_exit", Attr, IRB.getVoidTy());
  TrecIgnoreBegin = M.getOrInsertFunction("__trec_ignore_thread_begin", Attr,
                                          IRB.getVoidTy());
  TrecIgnoreEnd =
      M.getOrInsertFunction("__trec_ignore_thread_end", Attr, IRB.getVoidTy());
  IntegerType *OrdTy = IRB.getInt32Ty();
  for (size_t i = 0; i < kNumberOfAccessSizes; ++i) {
    const unsigned ByteSize = 1U << i;
    const unsigned BitSize = ByteSize * 8;
    std::string ByteSizeStr = utostr(ByteSize);
    std::string BitSizeStr = utostr(BitSize);
    SmallString<32> ReadName("__trec_read" + ByteSizeStr);
    if (i < 4)
      TrecRead[i] = M.getOrInsertFunction(
          ReadName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt1Ty(),
          IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IRB.getInt8Ty());
    else
      TrecRead[i] = M.getOrInsertFunction(
          ReadName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt1Ty(),
          IRB.getInt128Ty(), IRB.getInt8PtrTy(), IRB.getInt8Ty());
    SmallString<32> WriteName("__trec_write" + ByteSizeStr);
    if (i < 4)
      TrecWrite[i] = M.getOrInsertFunction(
          WriteName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt1Ty(),
          IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IRB.getInt8Ty(),
          IRB.getInt8PtrTy(), IRB.getInt8Ty());
    else
      TrecWrite[i] = M.getOrInsertFunction(
          WriteName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt1Ty(),
          IRB.getInt128Ty(), IRB.getInt8PtrTy(), IRB.getInt8Ty(),
          IRB.getInt8PtrTy(), IRB.getInt8Ty());
    SmallString<64> UnalignedReadName("__trec_unaligned_read" + ByteSizeStr);
    if (i < 4)
      TrecUnalignedRead[i] = M.getOrInsertFunction(
          UnalignedReadName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(),
          IRB.getInt1Ty(), IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
          IRB.getInt8Ty());
    else
      TrecUnalignedRead[i] = M.getOrInsertFunction(
          UnalignedReadName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(),
          IRB.getInt1Ty(), IRB.getInt128Ty(), IRB.getInt8PtrTy(),
          IRB.getInt8Ty());

    SmallString<64> UnalignedWriteName("__trec_unaligned_write" + ByteSizeStr);
    if (i < 4)
      TrecUnalignedWrite[i] = M.getOrInsertFunction(
          UnalignedWriteName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(),
          IRB.getInt1Ty(), IRB.getInt8PtrTy(), IRB.getInt8PtrTy(),
          IRB.getInt8Ty(), IRB.getInt8PtrTy(), IRB.getInt8Ty());
    else
      TrecUnalignedWrite[i] = M.getOrInsertFunction(
          UnalignedWriteName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(),
          IRB.getInt1Ty(), IRB.getInt128Ty(), IRB.getInt8PtrTy(),
          IRB.getInt8Ty(), IRB.getInt8PtrTy(), IRB.getInt8Ty());

    SmallString<64> CompoundRWName("__trec_read_write" + ByteSizeStr);
    TrecCompoundRW[i] = M.getOrInsertFunction(
        CompoundRWName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy());

    SmallString<64> UnalignedCompoundRWName("__trec_unaligned_read_write" +
                                            ByteSizeStr);
    TrecUnalignedCompoundRW[i] = M.getOrInsertFunction(
        UnalignedCompoundRWName, Attr, IRB.getVoidTy(), IRB.getInt8PtrTy());

    Type *Ty = Type::getIntNTy(M.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *BoolTy = Type::getInt1Ty(M.getContext());
    SmallString<32> AtomicLoadName("__trec_atomic" + BitSizeStr + "_load");
    TrecAtomicLoad[i] =
        M.getOrInsertFunction(AtomicLoadName, Attr, Ty, PtrTy, OrdTy, BoolTy);

    SmallString<32> AtomicStoreName("__trec_atomic" + BitSizeStr + "_store");
    TrecAtomicStore[i] = M.getOrInsertFunction(
        AtomicStoreName, Attr, IRB.getVoidTy(), PtrTy, Ty, OrdTy, BoolTy);

    for (unsigned Op = AtomicRMWInst::FIRST_BINOP;
         Op <= AtomicRMWInst::LAST_BINOP; ++Op) {
      TrecAtomicRMW[Op][i] = nullptr;
      const char *NamePart = nullptr;
      if (Op == AtomicRMWInst::Xchg)
        NamePart = "_exchange";
      else if (Op == AtomicRMWInst::Add)
        NamePart = "_fetch_add";
      else if (Op == AtomicRMWInst::Sub)
        NamePart = "_fetch_sub";
      else if (Op == AtomicRMWInst::And)
        NamePart = "_fetch_and";
      else if (Op == AtomicRMWInst::Or)
        NamePart = "_fetch_or";
      else if (Op == AtomicRMWInst::Xor)
        NamePart = "_fetch_xor";
      else if (Op == AtomicRMWInst::Nand)
        NamePart = "_fetch_nand";
      else
        continue;
      SmallString<32> RMWName("__trec_atomic" + itostr(BitSize) + NamePart);
      TrecAtomicRMW[Op][i] =
          M.getOrInsertFunction(RMWName, Attr, Ty, PtrTy, Ty, OrdTy, BoolTy);
    }

    SmallString<32> AtomicCASName("__trec_atomic" + BitSizeStr +
                                  "_compare_exchange_val");
    TrecAtomicCAS[i] = M.getOrInsertFunction(AtomicCASName, Attr, Ty, PtrTy, Ty,
                                             Ty, OrdTy, OrdTy, BoolTy);
  }
  TrecAtomicThreadFence = M.getOrInsertFunction("__trec_atomic_thread_fence",
                                                Attr, IRB.getVoidTy(), OrdTy);
  TrecAtomicSignalFence = M.getOrInsertFunction("__trec_atomic_signal_fence",
                                                Attr, IRB.getVoidTy(), OrdTy);

  MemmoveFn =
      M.getOrInsertFunction("memmove", Attr, IRB.getInt8PtrTy(),
                            IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy);
  MemcpyFn =
      M.getOrInsertFunction("memcpy", Attr, IRB.getInt8PtrTy(),
                            IRB.getInt8PtrTy(), IRB.getInt8PtrTy(), IntptrTy);
  MemsetFn =
      M.getOrInsertFunction("memset", Attr, IRB.getInt8PtrTy(),
                            IRB.getInt8PtrTy(), IRB.getInt32Ty(), IntptrTy);
  TrecBranch = M.getOrInsertFunction("__trec_branch", Attr, IRB.getVoidTy());
  TrecFuncParam = M.getOrInsertFunction("__trec_func_param", Attr,
                                        IRB.getVoidTy(), IRB.getInt8Ty(),
                                        IRB.getInt8PtrTy(), IRB.getInt8Ty());
  TrecFuncExitParam =
      M.getOrInsertFunction("__trec_func_exit_param", Attr, IRB.getVoidTy(),
                            IRB.getInt8PtrTy(), IRB.getInt8Ty());
  TrecFuncEnterOrder = M.getOrInsertFunction("__trec_func_enter_order", Attr,
                                             IRB.getVoidTy(), IRB.getInt8Ty());
}

static bool isVtableAccess(Instruction *I) {
  if (MDNode *Tag = I->getMetadata(LLVMContext::MD_tbaa))
    return Tag->isTBAAVtableAccess();
  return false;
}

static bool isAtomic(Instruction *I) {
  // TODO: Ask TTI whether synchronization scope is between threads.
  if (LoadInst *LI = dyn_cast<LoadInst>(I))
    return LI->isAtomic() && LI->getSyncScopeID() != SyncScope::SingleThread;
  if (StoreInst *SI = dyn_cast<StoreInst>(I))
    return SI->isAtomic() && SI->getSyncScopeID() != SyncScope::SingleThread;
  if (isa<AtomicRMWInst>(I))
    return true;
  if (isa<AtomicCmpXchgInst>(I))
    return true;
  if (isa<FenceInst>(I))
    return true;
  return false;
}

bool TraceRecorder::sanitizeFunction(Function &F,
                                     const TargetLibraryInfo &TLI) {
  // This is required to prevent instrumenting call to __trec_init from
  // within the module constructor.
  if (F.getName() == kTrecModuleCtorName)
    return false;
  // Naked functions can not have prologue/epilogue
  // (__trec_func_entry/__trec_func_exit) generated, so don't
  // instrument them at all.
  if (F.hasFnAttribute(Attribute::Naked))
    return false;
  initialize(*F.getParent());
  FuncCallOrders.clear();
  FuncCallOrderCounter = F.arg_size() + 1;
  SmallVector<InstructionInfo> AllLoadsAndStores;
  SmallVector<Instruction *> AtomicAccesses;
  SmallVector<Instruction *> MemIntrinCalls;
  SmallVector<Instruction *> Branches;
  SmallVector<Instruction *> ParamFuncCalls;
  SmallVector<Instruction *> FuncCalls;
  SmallVector<Instruction *> Returns;
  bool Res = false;
  bool HasCalls = false;
  const DataLayout &DL = F.getParent()->getDataLayout();

  for (auto &BB : F) {
    for (auto &Inst : BB) {
      if (isAtomic(&Inst))
        AtomicAccesses.push_back(&Inst);
    }
  }
  if (ClInstrumentAtomics)
    for (auto Inst : AtomicAccesses) {
      Res |= instrumentAtomic(Inst, DL);
    }

  // Traverse all instructions, collect loads/stores/returns, check for calls.
  for (auto &BB : F) {
    for (auto &Inst : BB) {
      if (isa<LoadInst>(Inst) || isa<StoreInst>(Inst))
        AllLoadsAndStores.emplace_back(InstructionInfo(&Inst));
      else if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst) ||
               isa<CallBrInst>(Inst)) {
        if (!dyn_cast<CallBase>(&Inst)
                 ->getFunctionType()
                 ->getReturnType()
                 ->isVoidTy())
          FuncCalls.push_back(&Inst);
        if (CallInst *CI = dyn_cast<CallInst>(&Inst)) {
          maybeMarkSanitizerLibraryCallNoBuiltin(CI, &TLI);
          if (CI->arg_size() &&
              !(CI->getCalledFunction() &&
                CI->getCalledFunction()->getName().startswith("llvm.dbg."))) {
            ParamFuncCalls.push_back(&Inst);
          }
          if (CI->getCalledFunction() == nullptr)
            Branches.push_back(&Inst); // indirect function call
        } else if (InvokeInst *II = dyn_cast<InvokeInst>(&Inst)) {
          if (II->getCalledFunction() == nullptr)
            Branches.push_back(&Inst);
          if (II->arg_size()) {
            ParamFuncCalls.push_back(&Inst);
          }
        } else if (CallBrInst *II = dyn_cast<CallBrInst>(&Inst)) {
          if (II->getCalledFunction() == nullptr)
            Branches.push_back(&Inst);
          if (II->arg_size()) {
            ParamFuncCalls.push_back(&Inst);
          }
        }
        if (isa<MemIntrinsic>(Inst))
          MemIntrinCalls.push_back(&Inst);
        HasCalls = true;
      } else if (isa<BranchInst>(Inst) &&
                 dyn_cast<BranchInst>(&Inst)->isConditional()) {
        Branches.push_back(&Inst); // conditional branch

      } else if (isa<SwitchInst>(Inst) || isa<IndirectBrInst>(Inst) ||
                 isa<SelectInst>(Inst)) {
        Branches.push_back(&Inst); // switch and indirect branch
      } else if (isa<ReturnInst>(Inst)) {
        Returns.push_back(&Inst); // function return
      }
    }
  }

  if (F.getName().find("__atomic_base") != llvm::StringRef::npos)
    Branches.clear();

  // We have collected all loads and stores.
  // FIXME: many of these accesses do not need to be checked for races
  // (e.g. variables that do not escape, etc).

  // Instrument atomic memory accesses in any case (they can be used to
  // implement synchronization).

  if (ClInstrumentMemIntrinsics)
    for (auto Inst : MemIntrinCalls) {
      Res |= instrumentMemIntrinsic(Inst);
    }
  if (ClInstrumentBranch)
    for (auto Inst : Branches) {
      Res |= instrumentBranch(Inst, DL);
    }
  if (ClInstrumentFuncParam) {
    for (auto Inst : FuncCalls) {
      Res |= instrumentFunctionCall(Inst);
    }
    for (auto Inst : Returns) {
      Res |= instrumentFunctionReturn(Inst);
    }
    for (auto Inst : ParamFuncCalls) {
      Res |= instrumentFunctionParamCall(Inst);
    }
  }

  // Instrument memory accesses only if we want to report bugs in the function.
  if (ClInstrumentMemoryAccesses)
    for (const auto &II : AllLoadsAndStores) {
      Res |= instrumentLoadOrStore(II, DL);
    }

  // Instrument function entry/exit points if there were instrumented
  // accesses.
  if ((F.arg_size() != 0 || !F.getReturnType()->isVoidTy()) &&
      ClInstrumentFuncEntryExit) {
    IRBuilder<> IRB(F.getEntryBlock().getFirstNonPHI());
    Value *ReturnAddress = IRB.CreateCall(
        Intrinsic::getDeclaration(F.getParent(), Intrinsic::returnaddress),
        IRB.getInt32(0));
    IRB.CreateCall(TrecFuncEntry, ReturnAddress);

    EscapeEnumerator EE(F);
    while (IRBuilder<> *AtExit = EE.Next()) {
      AtExit->CreateCall(TrecFuncExit, {});
    }
    Res |= true;
  }
  return Res;
}

bool TraceRecorder::instrumentBranch(Instruction *I, const DataLayout &DL) {
  IRBuilder<> IRB(I);
  IRB.CreateCall(TrecBranch, {});
  return true;
}

bool TraceRecorder::instrumentFunctionCall(Instruction *I) {
  IRBuilder<> IRB(I);
  FuncCallOrders.insert(std::make_pair(I, FuncCallOrderCounter));
  IRB.CreateCall(TrecFuncEnterOrder, {IRB.getInt8(FuncCallOrderCounter)});
  FuncCallOrderCounter += 1;
  return true;
}

bool TraceRecorder::instrumentFunctionReturn(Instruction *I) {
  IRBuilder<> IRB(I);
  ValSourceInfo VSI_val;
  VSI_val.Addr = nullptr;
  VSI_val.Idx = 0;
  Value *RetVal = dyn_cast<ReturnInst>(I)->getReturnValue();
  bool res = false;
  if (RetVal) {
    getSource(RetVal, I->getParent()->getParent(), VSI_val);
    IRB.CreateCall(
        TrecFuncExitParam,
        {IRB.CreatePointerCast((VSI_val.Addr ? VSI_val.Addr : IRB.getInt8(0)),
                               IRB.getInt8PtrTy()),
         IRB.getInt8(VSI_val.Idx)});
    res = true;
  }

  return res;
}

bool TraceRecorder::instrumentFunctionParamCall(Instruction *I) {
  IRBuilder<> IRB(I);
  CallBase *CI = dyn_cast<CallBase>(I);
  unsigned int arg_size = CI->arg_size();
  IRB.CreateCall(TrecFuncParam,
                 {IRB.getInt8(0),
                  IRB.CreatePointerCast(IRB.getInt8(0), IRB.getInt8PtrTy()),
                  IRB.getInt8(arg_size)});
  for (unsigned int i = 0; i < arg_size; i++) {
    ValSourceInfo VSI;
    getSource(CI->getArgOperand(i), I->getParent()->getParent(), VSI);
    if (VSI.Addr || VSI.Idx) {
      IRB.CreateCall(TrecFuncParam, {IRB.getInt8(i + 1),
                                     IRB.CreatePointerCast(
                                         (VSI.Addr ? VSI.Addr : IRB.getInt8(0)),
                                         IRB.getInt8PtrTy()),
                                     IRB.getInt8(VSI.Idx)});
    }
  }
  return true;
}

bool TraceRecorder::instrumentLoadOrStore(const InstructionInfo &II,
                                          const DataLayout &DL) {
  IRBuilder<> IRB(II.Inst);
  const bool IsWrite = isa<StoreInst>(*II.Inst);
  Value *Addr = IsWrite ? cast<StoreInst>(II.Inst)->getPointerOperand()
                        : cast<LoadInst>(II.Inst)->getPointerOperand();

  // swifterror memory addresses are mem2reg promoted by instruction
  // selection. As such they cannot have regular uses like an instrumentation
  // function and it makes no sense to track them as memory.

  if (Addr->isSwiftError())
    return false;

  int Idx = getMemoryAccessFuncIndex(Addr, DL);
  if (Idx < 0 || Idx > 4)
    return false;

  // never instrument vtable update/read operations
  if (isVtableAccess(II.Inst)) {
    return false;
  }

  const unsigned Alignment = IsWrite ? cast<StoreInst>(II.Inst)->getAlignment()
                                     : cast<LoadInst>(II.Inst)->getAlignment();

  Type *OrigTy = cast<PointerType>(Addr->getType())->getElementType();
  const bool isPtrTy = isa<PointerType>(OrigTy);
  const uint32_t TypeSize = DL.getTypeStoreSizeInBits(OrigTy);
  FunctionCallee OnAccessFunc = nullptr;
  if (Alignment == 0 || Alignment >= 8 || (Alignment % (TypeSize / 8)) == 0) {
    OnAccessFunc = IsWrite ? TrecWrite[Idx] : TrecRead[Idx];
  } else {
    OnAccessFunc = IsWrite ? TrecUnalignedWrite[Idx] : TrecUnalignedRead[Idx];
  }

  ValSourceInfo VSI_addr;
  getSource(Addr, II.Inst->getParent()->getParent(), VSI_addr);

  if (IsWrite) {

    Value *StoredValue = cast<StoreInst>(II.Inst)->getValueOperand();
    ValSourceInfo VSI_val;
    getSource(StoredValue, II.Inst->getParent()->getParent(), VSI_val);
    if (isa<VectorType>(StoredValue->getType())) {
      switch (Idx) {
      case 0:
        StoredValue = IRB.CreateBitCast(StoredValue, IRB.getInt8Ty());
        break;
      case 1:
        StoredValue = IRB.CreateBitCast(StoredValue, IRB.getInt16Ty());
        break;
      case 2:
        StoredValue = IRB.CreateBitCast(StoredValue, IRB.getInt32Ty());
        break;
      case 3:
        StoredValue = IRB.CreateBitCast(StoredValue, IRB.getInt64Ty());
        break;
      case 4:
        StoredValue = IRB.CreateBitCast(StoredValue, IRB.getInt128Ty());
        break;
      }
    }

    if (Idx < 4) {
      if (!StoredValue->getType()->isIntegerTy()) {
        switch (Idx) {
        case 0:
          StoredValue =
              IRB.CreateBitOrPointerCast(StoredValue, IRB.getInt8Ty());
          break;
        case 1:
          StoredValue =
              IRB.CreateBitOrPointerCast(StoredValue, IRB.getInt16Ty());
          break;
        case 2:
          StoredValue =
              IRB.CreateBitOrPointerCast(StoredValue, IRB.getInt32Ty());
          break;
        case 3:
          StoredValue =
              IRB.CreateBitOrPointerCast(StoredValue, IRB.getInt64Ty());
          break;
        }
      }
      StoredValue = IRB.CreateIntToPtr(StoredValue, IRB.getInt8PtrTy());

      IRB.CreateCall(
          OnAccessFunc,
          {IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()),
           IRB.getInt1(isPtrTy),
           IRB.CreatePointerCast(StoredValue, IRB.getInt8PtrTy()),
           IRB.CreatePointerCast(
               (VSI_addr.Addr ? VSI_addr.Addr : IRB.getInt8(0)),
               IRB.getInt8PtrTy()),
           IRB.getInt8(VSI_addr.Idx),
           IRB.CreatePointerCast((VSI_val.Addr ? VSI_val.Addr : IRB.getInt8(0)),
                                 IRB.getInt8PtrTy()),
           IRB.getInt8(VSI_val.Idx)});

    } else {
      IRB.CreateCall(
          OnAccessFunc,
          {IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()),
           IRB.getInt1(isPtrTy),
           IRB.CreateBitCast(StoredValue, IRB.getInt128Ty()),
           IRB.CreatePointerCast(
               (VSI_addr.Addr ? VSI_addr.Addr : IRB.getInt8(0)),
               IRB.getInt8PtrTy()),
           IRB.getInt8(VSI_addr.Idx),
           IRB.CreatePointerCast((VSI_val.Addr ? VSI_val.Addr : IRB.getInt8(0)),
                                 IRB.getInt8PtrTy()),
           IRB.getInt8(VSI_val.Idx)});
    }
    NumInstrumentedWrites++;
  } else {
    if (II.Inst->getNextNode() == nullptr) {
      return false;
    }
    // just for recording the PC number
    IRB.CreateCall(OnAccessFunc,
                   {IRB.CreatePointerCast(Addr, IRB.getInt8PtrTy()),
                    IRB.getInt1(isPtrTy),
                    IRB.CreateIntToPtr(IRB.getInt8(0), IRB.getInt8PtrTy()),
                    IRB.CreatePointerCast(IRB.getInt8(0), IRB.getInt8PtrTy()),
                    IRB.getInt8(0)});
    // read inst should not be the last inst in a BB, thus no need to check
    // for nullptr
    IRBuilder<> IRB2(II.Inst->getNextNode());
    Value *LoadedValue = II.Inst;
    if (isa<VectorType>(LoadedValue->getType())) {
      switch (Idx) {
      case 0:
        LoadedValue = IRB2.CreateBitCast(LoadedValue, IRB2.getInt8Ty());
        break;
      case 1:
        LoadedValue = IRB2.CreateBitCast(LoadedValue, IRB2.getInt16Ty());
        break;
      case 2:
        LoadedValue = IRB2.CreateBitCast(LoadedValue, IRB2.getInt32Ty());
        break;
      case 3:
        LoadedValue = IRB2.CreateBitCast(LoadedValue, IRB2.getInt64Ty());
        break;
      case 4:
        LoadedValue = IRB2.CreateBitCast(LoadedValue, IRB2.getInt128Ty());
        break;
      }
    }
    if (Idx < 4) {
      if (!LoadedValue->getType()->isIntegerTy()) {
        switch (Idx) {
        case 0:
          LoadedValue =
              IRB2.CreateBitOrPointerCast(LoadedValue, IRB2.getInt8Ty());
          break;
        case 1:
          LoadedValue =
              IRB2.CreateBitOrPointerCast(LoadedValue, IRB2.getInt16Ty());
          break;
        case 2:
          LoadedValue =
              IRB2.CreateBitOrPointerCast(LoadedValue, IRB2.getInt32Ty());
          break;
        case 3:
          LoadedValue =
              IRB2.CreateBitOrPointerCast(LoadedValue, IRB2.getInt64Ty());
          break;
        }
      }
      LoadedValue = IRB2.CreateIntToPtr(LoadedValue, IRB2.getInt8PtrTy());
      IRB2.CreateCall(OnAccessFunc,
                      {IRB2.CreatePointerCast(Addr, IRB2.getInt8PtrTy()),
                       IRB2.getInt1(isPtrTy),
                       IRB2.CreatePointerCast(LoadedValue, IRB2.getInt8PtrTy()),
                       IRB2.CreatePointerCast(
                           (VSI_addr.Addr ? VSI_addr.Addr : IRB2.getInt8(0)),
                           IRB2.getInt8PtrTy()),
                       IRB2.getInt8(VSI_addr.Idx)});
    } else {
      IRB2.CreateCall(OnAccessFunc,
                      {IRB2.CreatePointerCast(Addr, IRB2.getInt8PtrTy()),
                       IRB2.getInt1(isPtrTy),
                       IRB2.CreateBitCast(LoadedValue, IRB2.getInt128Ty()),
                       IRB2.CreatePointerCast(
                           (VSI_addr.Addr ? VSI_addr.Addr : IRB2.getInt8(0)),
                           IRB2.getInt8PtrTy()),
                       IRB2.getInt8(VSI_addr.Idx)});
    }

    NumInstrumentedReads++;
  }
  return true;
}

void TraceRecorder::getSource(Value *Val, Function *F,
                              TraceRecorder::ValSourceInfo &VSI) {
  VSI.Addr = nullptr;
  VSI.Idx = 0;
  size_t arg_num = F->arg_size();
  SmallVector<Value *, 2> possibleValues;
  possibleValues.push_back(Val);
  while (!possibleValues.empty()) {
    Value *SrcValue = possibleValues.back();
    possibleValues.pop_back();
    while (isa<LoadInst>(SrcValue) || isa<CastInst>(SrcValue) ||
           isa<GetElementPtrInst>(SrcValue) || isa<BinaryOperator>(SrcValue)) {
      if (isa<LoadInst>(SrcValue)) {
        // get source address
        VSI.Addr = dyn_cast<LoadInst>(SrcValue)->getPointerOperand();
        return;
      } else if (isa<CastInst>(SrcValue)) {
        // cast inst, get its source value
        SrcValue = dyn_cast<CastInst>(SrcValue)->getOperand(0);
      } else if (isa<GetElementPtrInst>(SrcValue)) {
        // GEP inst, get its source value
        SrcValue = dyn_cast<GetElementPtrInst>(SrcValue)->getPointerOperand();
      } else if (isa<BinaryOperator>(SrcValue)) {
        BinaryOperator *I = dyn_cast<BinaryOperator>(SrcValue);
        possibleValues.push_back(I->getOperand(0));
        possibleValues.push_back(I->getOperand(1));
        break;
      }
    }
    if (isa<CallInst>(SrcValue) || isa<InvokeInst>(SrcValue) ||
        isa<CallBrInst>(SrcValue)) {
      if (FuncCallOrders.find(dyn_cast<Instruction>(SrcValue)) !=
          FuncCallOrders.end()) {
        VSI.Idx = FuncCallOrders[dyn_cast<Instruction>(SrcValue)];
        return;
      }
    } else if (!isa<Instruction>(SrcValue) && arg_num) {
      for (unsigned int i = 0; i < arg_num; i++) {
        Value *arg = F->getArg(i);
        if (SrcValue == arg) {
          VSI.Idx = i + 1;
          return;
        }
      }
    }
  }
  return;
}

static ConstantInt *createOrdering(IRBuilder<> *IRB, AtomicOrdering ord) {
  uint32_t v = 0;
  switch (ord) {
  case AtomicOrdering::NotAtomic:
    llvm_unreachable("unexpected atomic ordering!");
  case AtomicOrdering::Unordered:
    LLVM_FALLTHROUGH;
  case AtomicOrdering::Monotonic:
    v = 0;
    break;
  // Not specified yet:
  // case AtomicOrdering::Consume:                v = 1; break;
  case AtomicOrdering::Acquire:
    v = 2;
    break;
  case AtomicOrdering::Release:
    v = 3;
    break;
  case AtomicOrdering::AcquireRelease:
    v = 4;
    break;
  case AtomicOrdering::SequentiallyConsistent:
    v = 5;
    break;
  }
  return IRB->getInt32(v);
}

// If a memset intrinsic gets inlined by the code gen, we will miss races on
// it. So, we either need to ensure the intrinsic is not inlined, or
// instrument it. We do not instrument memset/memmove/memcpy intrinsics (too
// complicated), instead we simply replace them with regular function calls,
// which are then intercepted by the run-time. Since trec is running after
// everyone else, the calls should not be replaced back with intrinsics. If
// that becomes wrong at some point, we will need to call e.g. __trec_memset
// to avoid the intrinsics.
bool TraceRecorder::instrumentMemIntrinsic(Instruction *I) {
  IRBuilder<> IRB(I);
  if (MemSetInst *M = dyn_cast<MemSetInst>(I)) {
    IRB.CreateCall(
        MemsetFn,
        {IRB.CreatePointerCast(M->getArgOperand(0), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(M->getArgOperand(1), IRB.getInt32Ty(), false),
         IRB.CreateIntCast(M->getArgOperand(2), IntptrTy, false)});
    I->eraseFromParent();
  } else if (MemTransferInst *M = dyn_cast<MemTransferInst>(I)) {
    IRB.CreateCall(
        isa<MemCpyInst>(M) ? MemcpyFn : MemmoveFn,
        {IRB.CreatePointerCast(M->getArgOperand(0), IRB.getInt8PtrTy()),
         IRB.CreatePointerCast(M->getArgOperand(1), IRB.getInt8PtrTy()),
         IRB.CreateIntCast(M->getArgOperand(2), IntptrTy, false)});
    I->eraseFromParent();
  }
  return false;
}

// Both llvm and TraceRecorder atomic operations are based on C++11/C1x
// standards.  For background see C++11 standard.  A slightly older, publicly
// available draft of the standard (not entirely up-to-date, but close enough
// for casual browsing) is available here:
// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2011/n3242.pdf
// The following page contains more background information:
// http://www.hpl.hp.com/personal/Hans_Boehm/c++mm/

bool TraceRecorder::instrumentAtomic(Instruction *I, const DataLayout &DL) {
  IRBuilder<> IRB(I);
  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
    Value *Addr = LI->getPointerOperand();
    int Idx = getMemoryAccessFuncIndex(Addr, DL);
    if (Idx < 0)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = cast<PointerType>(Addr->getType())->getElementType();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     createOrdering(&IRB, LI->getOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy())};

    Value *C = IRB.CreateCall(TrecAtomicLoad[Idx], Args);
    Value *Cast = IRB.CreateBitOrPointerCast(C, OrigTy);
    I->replaceAllUsesWith(Cast);
  } else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    Value *Addr = SI->getPointerOperand();
    int Idx = getMemoryAccessFuncIndex(Addr, DL);
    if (Idx < 0)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = cast<PointerType>(Addr->getType())->getElementType();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     IRB.CreateBitOrPointerCast(SI->getValueOperand(), Ty),
                     createOrdering(&IRB, SI->getOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy())};
    CallInst *C = CallInst::Create(TrecAtomicStore[Idx], Args);
    ReplaceInstWithInst(I, C);
  } else if (AtomicRMWInst *RMWI = dyn_cast<AtomicRMWInst>(I)) {
    Value *Addr = RMWI->getPointerOperand();
    int Idx = getMemoryAccessFuncIndex(Addr, DL);
    if (Idx < 0)
      return false;
    FunctionCallee F = TrecAtomicRMW[RMWI->getOperation()][Idx];
    if (!F)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = cast<PointerType>(Addr->getType())->getElementType();
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     IRB.CreateIntCast(RMWI->getValOperand(), Ty, false),
                     createOrdering(&IRB, RMWI->getOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy())};
    CallInst *C = CallInst::Create(F, Args);
    ReplaceInstWithInst(I, C);
  } else if (AtomicCmpXchgInst *CASI = dyn_cast<AtomicCmpXchgInst>(I)) {
    Value *Addr = CASI->getPointerOperand();
    int Idx = getMemoryAccessFuncIndex(Addr, DL);
    if (Idx < 0)
      return false;
    const unsigned ByteSize = 1U << Idx;
    const unsigned BitSize = ByteSize * 8;
    Type *Ty = Type::getIntNTy(IRB.getContext(), BitSize);
    Type *PtrTy = Ty->getPointerTo();
    Type *OrigTy = cast<PointerType>(Addr->getType())->getElementType();
    Value *CmpOperand =
        IRB.CreateBitOrPointerCast(CASI->getCompareOperand(), Ty);
    Value *NewOperand =
        IRB.CreateBitOrPointerCast(CASI->getNewValOperand(), Ty);
    Value *Args[] = {IRB.CreatePointerCast(Addr, PtrTy),
                     CmpOperand,
                     NewOperand,
                     createOrdering(&IRB, CASI->getSuccessOrdering()),
                     createOrdering(&IRB, CASI->getFailureOrdering()),
                     IRB.getInt1(OrigTy->isPointerTy())};
    CallInst *C = IRB.CreateCall(TrecAtomicCAS[Idx], Args);
    Value *Success = IRB.CreateICmpEQ(C, CmpOperand);
    Value *OldVal = C;
    Type *OrigOldValTy = CASI->getNewValOperand()->getType();
    if (Ty != OrigOldValTy) {
      // The value is a pointer, so we need to cast the return value.
      OldVal = IRB.CreateIntToPtr(C, OrigOldValTy);
    }

    Value *Res =
        IRB.CreateInsertValue(UndefValue::get(CASI->getType()), OldVal, 0);
    Res = IRB.CreateInsertValue(Res, Success, 1);

    I->replaceAllUsesWith(Res);
    I->eraseFromParent();
  } else if (FenceInst *FI = dyn_cast<FenceInst>(I)) {
    Value *Args[] = {createOrdering(&IRB, FI->getOrdering())};
    FunctionCallee F = FI->getSyncScopeID() == SyncScope::SingleThread
                           ? TrecAtomicSignalFence
                           : TrecAtomicThreadFence;
    CallInst *C = CallInst::Create(F, Args);
    ReplaceInstWithInst(I, C);
  }
  return true;
}

int TraceRecorder::getMemoryAccessFuncIndex(Value *Addr, const DataLayout &DL) {
  Type *OrigPtrTy = Addr->getType();
  Type *OrigTy = cast<PointerType>(OrigPtrTy)->getElementType();
  assert(OrigTy->isSized());
  uint32_t TypeSize = DL.getTypeStoreSizeInBits(OrigTy);
  if (TypeSize != 8 && TypeSize != 16 && TypeSize != 32 && TypeSize != 64 &&
      TypeSize != 128) {
    NumAccessesWithBadSize++;
    // Ignore all unusual sizes.
    return -1;
  }
  size_t Idx = countTrailingZeros(TypeSize / 8);
  assert(Idx < kNumberOfAccessSizes);
  return Idx;
}
