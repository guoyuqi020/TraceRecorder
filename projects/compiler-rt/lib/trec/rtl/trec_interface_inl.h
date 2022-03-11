//===-- trec_interface_inl.h ------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder (TRec), a race detector.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_ptrauth.h"
#include "trec_interface.h"
#include "trec_rtl.h"

#define CALLERPC ((uptr)__builtin_return_address(0))

using namespace __trec;
using namespace __trec_metadata;
void __trec_branch() { CondBranch(cur_thread(), CALLERPC); }

void __trec_func_param(char param_idx, void *src_addr, char src_idx) {
  FuncParam(cur_thread(), param_idx, (uptr)src_addr, src_idx);
}

void __trec_func_exit_param(void *src_addr, char src_idx) {
  FuncExitParam(cur_thread(), (uptr)src_addr, src_idx);
}

void __trec_func_enter_order(char idx) { FuncEnterOrder(cur_thread(), idx); }

void __trec_read1(void *addr, bool isPtr, void *val, void *addr_src_addr,
                  char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, kSizeLog1, isPtr, (uptr)val,
             SAI_addr);
}

void __trec_read2(void *addr, bool isPtr, void *val, void *addr_src_addr,
                  char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, kSizeLog2, isPtr, (uptr)val,
             SAI_addr);
}

void __trec_read4(void *addr, bool isPtr, void *val, void *addr_src_addr,
                  char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, kSizeLog4, isPtr, (uptr)val,
             SAI_addr);
}

void __trec_read8(void *addr, bool isPtr, void *val, void *addr_src_addr,
                  char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, kSizeLog8, isPtr, (uptr)val,
             SAI_addr);
}

void __trec_write1(void *addr, bool isPtr, void *val, void *addr_src_addr,
                   char addr_src_idx, void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog1, isPtr, (uptr)val,
              SAI_addr, SAI_val);
}

void __trec_write2(void *addr, bool isPtr, void *val, void *addr_src_addr,
                   char addr_src_idx, void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog2, isPtr, (uptr)val,
              SAI_addr, SAI_val);
}

void __trec_write4(void *addr, bool isPtr, void *val, void *addr_src_addr,
                   char addr_src_idx, void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog4, isPtr, (uptr)val,
              SAI_addr, SAI_val);
}

void __trec_write8(void *addr, bool isPtr, void *val, void *addr_src_addr,
                   char addr_src_idx, void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog8, isPtr, (uptr)val,
              SAI_addr, SAI_val);
}

void __trec_func_entry(void *pc) {
  RecordFuncEntry(cur_thread(), STRIP_PC(pc));
  FuncEntry(cur_thread(), STRIP_PC(pc));
}

void __trec_func_exit() {
  RecordFuncExit(cur_thread());
  FuncExit(cur_thread());
}

void __trec_ignore_thread_begin() { ThreadIgnoreBegin(cur_thread(), CALLERPC); }

void __trec_ignore_thread_end() { ThreadIgnoreEnd(cur_thread(), CALLERPC); }

void __trec_read_range(void *addr, uptr size) {
  MemoryAccessRange(cur_thread(), CALLERPC, (uptr)addr, size, false);
}

void __trec_write_range(void *addr, uptr size) {
  MemoryAccessRange(cur_thread(), CALLERPC, (uptr)addr, size, true);
}

void __trec_read_range_pc(void *addr, uptr size, void *pc) {
  MemoryAccessRange(cur_thread(), STRIP_PC(pc), (uptr)addr, size, false);
}

void __trec_write_range_pc(void *addr, uptr size, void *pc) {
  MemoryAccessRange(cur_thread(), STRIP_PC(pc), (uptr)addr, size, true);
}
