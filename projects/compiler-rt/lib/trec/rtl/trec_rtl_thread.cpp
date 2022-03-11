//===-- trec_rtl_thread.cpp
//-----------------------------------------------===//
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

#include <errno.h>
#include <sys/fcntl.h>

#include "sanitizer_common/sanitizer_placement_new.h"
#include "trec_mman.h"
#include "trec_platform.h"
#include "trec_report.h"
#include "trec_rtl.h"
#include "trec_sync.h"

namespace __trec {

// ThreadContext implementation.

ThreadContext::ThreadContext(int tid)
    : ThreadContextBase(tid),
      thr(),
      trace_buffer(nullptr),
      metadata_buffer(nullptr),
      trace_buffer_size(0),
      metadata_buffer_size(0),
      event_cnt(0),
      metadata_offset(0),
      prev_read_pc(0),
      header(tid) {}

#if !SANITIZER_GO
ThreadContext::~ThreadContext() {}
#endif

void ThreadContext::OnDead() { CHECK_EQ(sync.size(), 0); }

void ThreadContext::OnJoined(void *arg) {
  ThreadState *caller_thr = static_cast<ThreadState *>(arg);
  AcquireImpl(caller_thr, 0, &sync);
  sync.Reset(&caller_thr->proc()->clock_cache);
}

struct OnCreatedArgs {
  ThreadState *thr;
  uptr pc;
};

void ThreadContext::OnCreated(void *arg) {
  thr = 0;
  if (tid == 0)
    return;
  OnCreatedArgs *args = static_cast<OnCreatedArgs *>(arg);
  if (!args->thr)  // GCD workers don't have a parent thread.
    return;
  args->thr->fast_state.IncrementEpoch();
  // Can't increment epoch w/o writing to the trace as well.
  TraceAddEvent(args->thr, args->thr->fast_state, EventTypeMop, 0);
  ReleaseImpl(args->thr, 0, &sync);
  creation_stack_id = CurrentStackId(args->thr, args->pc);
  if (reuse_count == 0)
    StatInc(args->thr, StatThreadMaxTid);
}

void ThreadContext::OnReset() {
  CHECK_EQ(sync.size(), 0);
  uptr trace_p = GetThreadTrace(tid);
  ReleaseMemoryPagesToOS(trace_p, trace_p + TraceSize() * sizeof(Event));
  //!!! ReleaseMemoryToOS(GetThreadTraceHeader(tid), sizeof(Trace));
}

void ThreadContext::OnDetached(void *arg) {
  ThreadState *thr1 = static_cast<ThreadState *>(arg);
  sync.Reset(&thr1->proc()->clock_cache);
}

bool ThreadContext::state_restore() {
  struct stat _st = {0};
  char path[512];
  internal_snprintf(path, 511, "%s/trec_%llu/header/%u.bin", ctx->trace_dir,
                    internal_getpid(), tid);
  uptr IS_EXIST = __sanitizer::internal_stat(path, &_st);
  if (IS_EXIST == 0 && _st.st_size > 0) {
    int header_fd = internal_open(path, O_RDONLY);
    if (header_fd < 0) {
      Report("Restore header from %s failed\n", path);
      return false;
    } else {
      internal_read(header_fd, &header, sizeof(header));
      event_cnt = header.state[__trec_header::RecordType::TotalEventCnt];
      metadata_offset =
          header.state[__trec_header::RecordType::MetadataFileLen];
      header.state[__trec_header::RecordType::ProcessFork] = 0;
      header.state[__trec_header::RecordType::Tid] = tid;
      return true;
    }
  }
  return false;
}

void ThreadContext::flush_trace() {
  char filepath[256];
  internal_snprintf(filepath, 255, "%s/trec_%d/trace/%d.bin", ctx->trace_dir,
                    internal_getpid(), thr->tid);
  int fd_trace = internal_open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0700);

  if (UNLIKELY(fd_trace < 0)) {
    Report("Failed to open trace file at %s\n", filepath);
    Die();
  } else if (trace_buffer != nullptr && trace_buffer_size > 0) {
    char *buff_pos = (char *)trace_buffer;
    while (trace_buffer_size > 0) {
      uptr write_bytes = internal_write(fd_trace, buff_pos, trace_buffer_size);
      if (write_bytes == -1 && errno != EINTR) {
        Report("Failed to flush metadata info in %s, errno=%u\n", filepath,
               errno);
        Die();
      } else {
        trace_buffer_size -= write_bytes;
        buff_pos += write_bytes;
      }
    }
  }
  internal_close(fd_trace);
  header.state[__trec_header::RecordType::TotalEventCnt] = event_cnt;
}

void ThreadContext::flush_metadata() {
  char filepath[256];
  internal_snprintf(filepath, 255, "%s/trec_%d/metadata/%d.bin", ctx->trace_dir,
                    internal_getpid(), thr->tid);
  int fd_metadata =
      internal_open(filepath, O_CREAT | O_WRONLY | O_APPEND, 0700);

  if (UNLIKELY(fd_metadata < 0)) {
    Report("Failed to open metadata file at %s\n", filepath);
    Die();
  } else if (metadata_buffer != nullptr && metadata_buffer_size > 0) {
    char *buff_pos = (char *)metadata_buffer;
    while (metadata_buffer_size > 0) {
      uptr write_bytes =
          internal_write(fd_metadata, buff_pos, metadata_buffer_size);
      if (write_bytes == -1 && errno != EINTR) {
        Report("Failed to flush metadata info in %s, errno=%u\n", filepath,
               errno);
        Die();
      } else {
        metadata_buffer_size -= write_bytes;
        buff_pos += write_bytes;
        header.state[__trec_header::RecordType::MetadataFileLen] += write_bytes;
      }
    }
  }
  internal_close(fd_metadata);
}

static inline bool CompareBaseAddress(const LoadedModule &a,
                                      const LoadedModule &b) {
  return a.base_address() < b.base_address();
}
void ThreadContext::flush_module() {
  char modulepath[256];
  char write_buff[512];
  internal_snprintf(modulepath, 255, "%s/trec_%d/header/modules_%d.txt",
                    ctx->trace_dir, internal_getpid(), thr->tid);
  int fd_module_file =
      internal_open(modulepath, O_CREAT | O_WRONLY | O_TRUNC, 0700);
  MemoryMappingLayout memory_mapping(false);
  InternalMmapVector<LoadedModule> modules(/*initial_capacity*/ 64);
  memory_mapping.DumpListOfModules(&modules);
  Sort(modules.begin(), modules.size(), CompareBaseAddress);
  uptr idx = 0;
  bool found = false;
  for (auto &item : modules) {
    if (item.full_name() && item.base_address() &&
        item.max_executable_address() &&
        internal_strstr(item.full_name(), "(deleted)") == nullptr) {
      if (!found) {
        internal_strlcpy(thr->tctx->header.binary_path, item.full_name(), 511);
        found = true;
      }
      internal_memset(write_buff, 0, sizeof(write_buff));
      int bufflen =
          internal_snprintf(write_buff, 511, "%s %p-%p\n", item.full_name(),
                            item.base_address(), item.max_executable_address());
      uptr need_write_bytes = bufflen;
      char *buff_pos = (char *)write_buff;
      while (need_write_bytes > 0) {
        uptr write_bytes =
            internal_write(fd_module_file, buff_pos, need_write_bytes);
        if (write_bytes == -1 && errno != EINTR) {
          Report("Failed to flush module info in %s, errno=%u\n", modulepath,
                 errno);
          Die();
        } else {
          need_write_bytes -= write_bytes;
          buff_pos += write_bytes;
        }
      }
    }
  }
  internal_close(fd_module_file);
}

void ThreadContext::flush_header() {
  char filepath[256];
  internal_snprintf(filepath, 255, "%s/trec_%d/header/%d.bin", ctx->trace_dir,
                    internal_getpid(), thr->tid);

  int fd_header = internal_open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0700);

  if (UNLIKELY(fd_header < 0)) {
    Report("Failed to open header file\n");
    Die();
  } else {
    uptr need_write_bytes = sizeof(header);
    char *buff_pos = (char *)&header;
    while (need_write_bytes > 0) {
      uptr write_bytes = internal_write(fd_header, buff_pos, need_write_bytes);
      if (write_bytes == -1 && errno != EINTR) {
        Report("Failed to flush header in %s, errno=%u\n", filepath, errno);
        Die();
      } else {
        need_write_bytes -= write_bytes;
        buff_pos += write_bytes;
      }
    }
  }

  internal_close(fd_header);
}

void ThreadContext::put_trace(void *msg, uptr len) {
  if (trace_buffer == nullptr) {
    trace_buffer = (char *)internal_alloc(MBlockShadowStack, TREC_BUFFER_SIZE);
    trace_buffer_size = 0;
  }
  if (trace_buffer_size + len >= TREC_BUFFER_SIZE) {
    flush_trace();
    flush_metadata();
    flush_header();
  }
  internal_memcpy(trace_buffer + trace_buffer_size, msg, len);
  trace_buffer_size += len;
  event_cnt += 1;
}

void ThreadContext::put_metadata(void *msg, uptr len) {
  if (metadata_buffer == nullptr) {
    metadata_buffer =
        (char *)internal_alloc(MBlockShadowStack, TREC_BUFFER_SIZE);
    metadata_buffer_size = 0;
  }
  if (metadata_buffer_size + len > TREC_BUFFER_SIZE) {
    flush_trace();
    flush_metadata();
    flush_header();
  }
  internal_memcpy(metadata_buffer + metadata_buffer_size, msg, len);
  metadata_buffer_size += len;
  metadata_offset += len;
}

struct OnStartedArgs {
  ThreadState *thr;
  uptr stk_addr;
  uptr stk_size;
  uptr tls_addr;
  uptr tls_size;
};

void ThreadContext::OnStarted(void *arg) {
  OnStartedArgs *args = static_cast<OnStartedArgs *>(arg);
  thr = args->thr;
  // RoundUp so that one trace part does not contain events
  // from different threads.
  epoch0 = RoundUp(epoch1 + 1, kTracePartSize);
  epoch1 = (u64)-1;
  new (thr)
      ThreadState(ctx, tid, epoch0, unique_id, reuse_count, args->stk_addr,
                  args->stk_size, args->tls_addr, args->tls_size);
#if !SANITIZER_GO
  thr->shadow_stack = &ThreadTrace(thr->tid)->shadow_stack[0];
  thr->shadow_stack_pos = thr->shadow_stack;
  thr->shadow_stack_end = thr->shadow_stack + kShadowStackSize;
#else
  // Setup dynamic shadow stack.
  const int kInitStackSize = 8;
  thr->shadow_stack =
      (uptr *)internal_alloc(MBlockShadowStack, kInitStackSize * sizeof(uptr));
  thr->shadow_stack_pos = thr->shadow_stack;
  thr->shadow_stack_end = thr->shadow_stack + kInitStackSize;
#endif
  if (common_flags()->detect_deadlocks)
    thr->dd_lt = ctx->dd->CreateLogicalThread(unique_id);
  thr->fast_state.SetHistorySize(flags()->history_size);
  // Commit switch to the new part of the trace.
  // TraceAddEvent will reset stack0/mset0 in the new part for us.
  TraceAddEvent(thr, thr->fast_state, EventTypeMop, 0);

  thr->fast_synch_epoch = epoch0;
  AcquireImpl(thr, 0, &sync);
  StatInc(thr, StatSyncAcquire);
  sync.Reset(&thr->proc()->clock_cache);
  thr->is_inited = true;
  DPrintf(
      "#%d: ThreadStart epoch=%zu stk_addr=%zx stk_size=%zx "
      "tls_addr=%zx tls_size=%zx\n",
      tid, (uptr)epoch0, args->stk_addr, args->stk_size, args->tls_addr,
      args->tls_size);
}

void ThreadContext::OnFinished() {
#if SANITIZER_GO
  internal_free(thr->shadow_stack);
  thr->shadow_stack = nullptr;
  thr->shadow_stack_pos = nullptr;
  thr->shadow_stack_end = nullptr;
#endif
  if (!detached) {
    thr->fast_state.IncrementEpoch();
    // Can't increment epoch w/o writing to the trace as well.
    TraceAddEvent(thr, thr->fast_state, EventTypeMop, 0);
    ReleaseImpl(thr, 0, &sync);
  }
  epoch1 = thr->fast_state.epoch();

  if (common_flags()->detect_deadlocks)
    ctx->dd->DestroyLogicalThread(thr->dd_lt);
  thr->clock.ResetCached(&thr->proc()->clock_cache);
#if !SANITIZER_GO
  thr->last_sleep_clock.ResetCached(&thr->proc()->clock_cache);
#endif
#if !SANITIZER_GO
  PlatformCleanUpThreadState(thr);
#endif
  thr->~ThreadState();
#if TREC_COLLECT_STATS
  StatAggregate(ctx->stat, thr->stat);
#endif
  thr = 0;
}

#if !SANITIZER_GO
struct ThreadLeak {
  ThreadContext *tctx;
  int count;
};

static void MaybeReportThreadLeak(ThreadContextBase *tctx_base, void *arg) {
  Vector<ThreadLeak> &leaks = *(Vector<ThreadLeak> *)arg;
  ThreadContext *tctx = static_cast<ThreadContext *>(tctx_base);
  if (tctx->detached || tctx->status != ThreadStatusFinished)
    return;
  for (uptr i = 0; i < leaks.Size(); i++) {
    if (leaks[i].tctx->creation_stack_id == tctx->creation_stack_id) {
      leaks[i].count++;
      return;
    }
  }
  ThreadLeak leak = {tctx, 1};
  leaks.PushBack(leak);
}
#endif

#if !SANITIZER_GO
static void ReportIgnoresEnabled(ThreadContext *tctx, IgnoreSet *set) {
  if (tctx->tid == 0) {
    Printf("TraceRecorder: main thread finished with ignores enabled\n");
  } else {
    Printf(
        "TraceRecorder: thread T%d %s finished with ignores enabled,"
        " created at:\n",
        tctx->tid, tctx->name);
    PrintStack(SymbolizeStackId(tctx->creation_stack_id));
  }
  Printf(
      "  One of the following ignores was not ended"
      " (in order of probability)\n");
  for (uptr i = 0; i < set->Size(); i++) {
    Printf("  Ignore was enabled at:\n");
    PrintStack(SymbolizeStackId(set->At(i)));
  }
  Die();
}

static void ThreadCheckIgnore(ThreadState *thr) {
  if (ctx->after_multithreaded_fork)
    return;
  if (thr->ignore_reads_and_writes)
    ReportIgnoresEnabled(thr->tctx, &thr->mop_ignore_set);
  if (thr->ignore_sync)
    ReportIgnoresEnabled(thr->tctx, &thr->sync_ignore_set);
}
#else
static void ThreadCheckIgnore(ThreadState *thr) {}
#endif

void ThreadFinalize(ThreadState *thr) {
  if (LIKELY(ctx->flags.output_trace)) {
    __trec_trace::Event e(
        __trec_trace::EventType::ThreadEnd,
        atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed),
        thr->tctx->metadata_offset);

    thr->tctx->put_trace(&e, sizeof(__trec_trace::Event));
    thr->tctx->flush_trace();
    thr->tctx->flush_metadata();
    thr->tctx->flush_header();
  }
  if (thr->tctx->trace_buffer) {
    internal_free(thr->tctx->trace_buffer);
    thr->tctx->trace_buffer = nullptr;
  }
  if (thr->tctx->metadata_buffer) {
    internal_free(thr->tctx->metadata_buffer);
    thr->tctx->metadata_buffer = nullptr;
  }
  thr->tctx->trace_buffer_size = 0;
  thr->tctx->metadata_buffer_size = 0;

  ThreadCheckIgnore(thr);
#if !SANITIZER_GO
  if (!flags()->report_thread_leaks)
    return;
  ThreadRegistryLock l(ctx->thread_registry);
  Vector<ThreadLeak> leaks;
  ctx->thread_registry->RunCallbackForEachThreadLocked(MaybeReportThreadLeak,
                                                       &leaks);
  for (uptr i = 0; i < leaks.Size(); i++) {
    ScopedReport rep(ReportTypeThreadLeak);
    rep.AddThread(leaks[i].tctx, true);
    rep.SetCount(leaks[i].count);
    OutputReport(thr, rep);
  }
#endif
}

int ThreadCount(ThreadState *thr) {
  uptr result;
  ctx->thread_registry->GetNumberOfThreads(0, 0, &result);
  return (int)result;
}

int ThreadCreate(ThreadState *thr, uptr pc, uptr uid, bool detached) {
  StatInc(thr, StatThreadCreate);
  OnCreatedArgs args = {thr, pc};
  u32 parent_tid = thr ? thr->tid : kInvalidTid;  // No parent for GCD workers.
  int tid =
      ctx->thread_registry->CreateThread(uid, detached, parent_tid, &args);
  DPrintf("#%d: ThreadCreate tid=%d uid=%zu\n", parent_tid, tid, uid);
  if (LIKELY(thr != nullptr && thr->tctx != nullptr)) {
    if (LIKELY(ctx->flags.output_trace)) {
      __trec_trace::Event e(
          __trec_trace::EventType::ThreadCreate,
          atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed),
          thr->tctx->metadata_offset);

      thr->tctx->put_trace(&e, sizeof(__trec_trace::Event));
      __trec_metadata::ThreadCreateJoinMeta meta(tid, pc);
      thr->tctx->put_metadata(&meta, sizeof(meta));
      thr->tctx->header.StateInc(__trec_header::RecordType::ThreadCreate);
    }
  }
  StatSet(thr, StatThreadMaxAlive, ctx->thread_registry->GetMaxAliveThreads());
  return tid;
}

void ThreadStart(ThreadState *thr, int tid, tid_t os_id,
                 ThreadType thread_type) {
  uptr stk_addr = 0;
  uptr stk_size = 0;
  uptr tls_addr = 0;
  uptr tls_size = 0;
#if !SANITIZER_GO
  if (thread_type != ThreadType::Fiber)
    GetThreadStackAndTls(tid == 0, &stk_addr, &stk_size, &tls_addr, &tls_size);

  if (tid) {
    if (stk_addr && stk_size)
      MemoryRangeImitateWrite(thr, /*pc=*/1, stk_addr, stk_size);

    if (tls_addr && tls_size)
      ImitateTlsWrite(thr, tls_addr, tls_size);
  }
#endif

  ThreadRegistry *tr = ctx->thread_registry;
  OnStartedArgs args = {thr, stk_addr, stk_size, tls_addr, tls_size};
  tr->StartThread(tid, os_id, thread_type, &args);

  tr->Lock();
  thr->tctx = (ThreadContext *)tr->GetThreadLocked(tid);
  tr->Unlock();

  // gyq: never touch this
  // we should put the trace after it thr->tctx has been initialized
  if (thr->tctx->trace_buffer) {
    internal_free(thr->tctx->trace_buffer);
    thr->tctx->trace_buffer = nullptr;
  }
  if (thr->tctx->metadata_buffer) {
    internal_free(thr->tctx->metadata_buffer);
    thr->tctx->metadata_buffer = nullptr;
  }
  if (!thr->tctx->state_restore()) {
    thr->tctx->trace_buffer_size = 0;
    thr->tctx->metadata_buffer_size = 0;
    thr->tctx->event_cnt = 0;
    thr->tctx->metadata_offset = 0;
    thr->tctx->prev_read_pc = 0;

    if (LIKELY(ctx->flags.output_trace)) {
      __trec_trace::Event e(
          __trec_trace::EventType::ThreadBegin,
          atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed),
          thr->tctx->metadata_offset);
      thr->tctx->put_trace(&e, sizeof(__trec_trace::Event));
    }
  }
  thr->tctx->flush_module();

#if !SANITIZER_GO
  if (ctx->after_multithreaded_fork) {
    thr->ignore_interceptors++;
    ThreadIgnoreBegin(thr, 0);
    ThreadIgnoreSyncBegin(thr, 0);
  }
#endif
}

void ThreadFinish(ThreadState *thr) {
  if (LIKELY(ctx->flags.output_trace)) {
    __trec_trace::Event e(
        __trec_trace::EventType::ThreadEnd,
        atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed),
        thr->tctx->metadata_offset);

    thr->tctx->put_trace(&e, sizeof(__trec_trace::Event));
    thr->tctx->flush_trace();
    thr->tctx->flush_metadata();
    thr->tctx->flush_header();
  }
  if (thr->tctx->trace_buffer) {
    internal_free(thr->tctx->trace_buffer);
    thr->tctx->trace_buffer = nullptr;
  }
  if (thr->tctx->metadata_buffer) {
    internal_free(thr->tctx->metadata_buffer);
    thr->tctx->metadata_buffer = nullptr;
  }
  thr->tctx->trace_buffer_size = 0;
  thr->tctx->metadata_buffer_size = 0;

  ThreadCheckIgnore(thr);
  StatInc(thr, StatThreadFinish);
  if (thr->stk_addr && thr->stk_size)
    DontNeedShadowFor(thr->stk_addr, thr->stk_size);
  if (thr->tls_addr && thr->tls_size)
    DontNeedShadowFor(thr->tls_addr, thr->tls_size);
  thr->is_dead = true;
  ctx->thread_registry->FinishThread(thr->tid);
}

struct ConsumeThreadContext {
  uptr uid;
  ThreadContextBase *tctx;
};

static bool ConsumeThreadByUid(ThreadContextBase *tctx, void *arg) {
  ConsumeThreadContext *findCtx = (ConsumeThreadContext *)arg;
  if (tctx->user_id == findCtx->uid && tctx->status != ThreadStatusInvalid) {
    if (findCtx->tctx) {
      // Ensure that user_id is unique. If it's not the case we are screwed.
      // Something went wrong before, but now there is no way to recover.
      // Returning a wrong thread is not an option, it may lead to very hard
      // to debug false positives (e.g. if we join a wrong thread).
      Report("TraceRecorder: dup thread with used id 0x%zx\n", findCtx->uid);
      Die();
    }
    findCtx->tctx = tctx;
    tctx->user_id = 0;
  }
  return false;
}

int ThreadConsumeTid(ThreadState *thr, uptr pc, uptr uid) {
  ConsumeThreadContext findCtx = {uid, nullptr};
  ctx->thread_registry->FindThread(ConsumeThreadByUid, &findCtx);
  int tid = findCtx.tctx ? findCtx.tctx->tid : ThreadRegistry::kUnknownTid;
  DPrintf("#%d: ThreadTid uid=%zu tid=%d\n", thr->tid, uid, tid);
  return tid;
}

void ThreadJoin(ThreadState *thr, uptr pc, int tid) {
  CHECK_GT(tid, 0);
  CHECK_LT(tid, kMaxTid);
  DPrintf("#%d: ThreadJoin tid=%d\n", thr->tid, tid);
  if (LIKELY(ctx->flags.output_trace)) {
    __trec_trace::Event e(
        __trec_trace::EventType::ThreadJoin,
        atomic_fetch_add(&ctx->global_id, 1, memory_order_relaxed),
        thr->tctx->metadata_offset);

    thr->tctx->put_trace(&e, sizeof(__trec_trace::Event));
    __trec_metadata::ThreadCreateJoinMeta meta(tid, pc);
    thr->tctx->put_metadata(&meta, sizeof(meta));
    thr->tctx->header.StateInc(__trec_header::RecordType::ThreadJoin);
  }
  ctx->thread_registry->JoinThread(tid, thr);
}

void ThreadDetach(ThreadState *thr, uptr pc, int tid) {
  CHECK_GT(tid, 0);
  CHECK_LT(tid, kMaxTid);
  ctx->thread_registry->DetachThread(tid, thr);
}

void ThreadNotJoined(ThreadState *thr, uptr pc, int tid, uptr uid) {
  CHECK_GT(tid, 0);
  CHECK_LT(tid, kMaxTid);
  ctx->thread_registry->SetThreadUserId(tid, uid);
}

void ThreadSetName(ThreadState *thr, const char *name) {
  ctx->thread_registry->SetThreadName(thr->tid, name);
}

void MemoryAccessRange(ThreadState *thr, uptr pc, uptr addr, uptr size,
                       bool is_write) {
  if (size == 0)
    return;

  u64 *shadow_mem = (u64 *)MemToShadow(addr);
  DPrintf2("#%d: MemoryAccessRange: @%p %p size=%d is_write=%d\n", thr->tid,
           (void *)pc, (void *)addr, (int)size, is_write);

#if SANITIZER_DEBUG
  if (!IsAppMem(addr)) {
    Printf("Access to non app mem %zx\n", addr);
    DCHECK(IsAppMem(addr));
  }
  if (!IsAppMem(addr + size - 1)) {
    Printf("Access to non app mem %zx\n", addr + size - 1);
    DCHECK(IsAppMem(addr + size - 1));
  }
  if (!IsShadowMem((uptr)shadow_mem)) {
    Printf("Bad shadow addr %p (%zx)\n", shadow_mem, addr);
    DCHECK(IsShadowMem((uptr)shadow_mem));
  }
  if (!IsShadowMem((uptr)(shadow_mem + size * kShadowCnt / 8 - 1))) {
    Printf("Bad shadow addr %p (%zx)\n", shadow_mem + size * kShadowCnt / 8 - 1,
           addr + size - 1);
    DCHECK(IsShadowMem((uptr)(shadow_mem + size * kShadowCnt / 8 - 1)));
  }
#endif

  StatInc(thr, StatMopRange);

  if (*shadow_mem == kShadowRodata) {
    DCHECK(!is_write);
    // Access to .rodata section, no races here.
    // Measurements show that it can be 10-20% of all memory accesses.
    StatInc(thr, StatMopRangeRodata);
    return;
  }

  FastState fast_state = thr->fast_state;
  if (fast_state.GetIgnoreBit())
    return;

  fast_state.IncrementEpoch();
  thr->fast_state = fast_state;
  TraceAddEvent(thr, fast_state, EventTypeMop, pc);

  bool unaligned = (addr % kShadowCell) != 0;

  // Handle unaligned beginning, if any.
  for (; addr % kShadowCell && size; addr++, size--) {
    int const kAccessSizeLog = 0;
    Shadow cur(fast_state);
    cur.SetWrite(is_write);
    cur.SetAddr0AndSizeLog(addr & (kShadowCell - 1), kAccessSizeLog);
    MemoryAccessImpl(thr, addr, kAccessSizeLog, is_write, false, shadow_mem,
                     cur);
  }
  if (unaligned)
    shadow_mem += kShadowCnt;
  // Handle middle part, if any.
  for (; size >= kShadowCell; addr += kShadowCell, size -= kShadowCell) {
    int const kAccessSizeLog = 3;
    Shadow cur(fast_state);
    cur.SetWrite(is_write);
    cur.SetAddr0AndSizeLog(0, kAccessSizeLog);
    MemoryAccessImpl(thr, addr, kAccessSizeLog, is_write, false, shadow_mem,
                     cur);
    shadow_mem += kShadowCnt;
  }
  // Handle ending, if any.
  for (; size; addr++, size--) {
    int const kAccessSizeLog = 0;
    Shadow cur(fast_state);
    cur.SetWrite(is_write);
    cur.SetAddr0AndSizeLog(addr & (kShadowCell - 1), kAccessSizeLog);
    MemoryAccessImpl(thr, addr, kAccessSizeLog, is_write, false, shadow_mem,
                     cur);
  }
}

#if !SANITIZER_GO
void FiberSwitchImpl(ThreadState *from, ThreadState *to) {
  Processor *proc = from->proc();
  ProcUnwire(proc, from);
  ProcWire(proc, to);
  set_cur_thread(to);
}

ThreadState *FiberCreate(ThreadState *thr, uptr pc, unsigned flags) {
  void *mem = internal_alloc(MBlockThreadContex, sizeof(ThreadState));
  ThreadState *fiber = static_cast<ThreadState *>(mem);
  internal_memset(fiber, 0, sizeof(*fiber));
  int tid = ThreadCreate(thr, pc, 0, true);
  FiberSwitchImpl(thr, fiber);
  ThreadStart(fiber, tid, 0, ThreadType::Fiber);
  FiberSwitchImpl(fiber, thr);
  return fiber;
}

void FiberDestroy(ThreadState *thr, uptr pc, ThreadState *fiber) {
  FiberSwitchImpl(thr, fiber);
  ThreadFinish(fiber);
  FiberSwitchImpl(fiber, thr);
  internal_free(fiber);
}

void FiberSwitch(ThreadState *thr, uptr pc, ThreadState *fiber,
                 unsigned flags) {
  if (!(flags & FiberSwitchFlagNoSync))
    Release(thr, pc, (uptr)fiber);
  FiberSwitchImpl(thr, fiber);
  if (!(flags & FiberSwitchFlagNoSync))
    Acquire(fiber, pc, (uptr)fiber);
}
#endif

}  // namespace __trec
