//===-- trec_defs.h ---------------------------------------------*- C++ -*-===//
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

#ifndef TREC_DEFS_H
#define TREC_DEFS_H

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "trec_stat.h"
#include "ubsan/ubsan_platform.h"

// Setup defaults for compile definitions.
#ifndef TREC_NO_HISTORY
#define TREC_NO_HISTORY 0
#endif

#ifndef TREC_COLLECT_STATS
#define TREC_COLLECT_STATS 0
#endif

#ifndef TREC_CONTAINS_UBSAN
#if CAN_SANITIZE_UB && !SANITIZER_GO
#define TREC_CONTAINS_UBSAN 1
#else
#define TREC_CONTAINS_UBSAN 0
#endif
#endif

#ifndef TREC_BUFFER_SIZE
#define TREC_BUFFER_SIZE (1 << 25)  // default buffer size: 32MB
#endif

namespace __trec {

const int kClkBits = 42;
const unsigned kMaxTidReuse = (1 << (64 - kClkBits)) - 1;

struct ClockElem {
  u64 epoch : kClkBits;
  u64 reused : 64 - kClkBits;  // tid reuse count
};

struct ClockBlock {
  static const uptr kSize = 512;
  static const uptr kTableSize = kSize / sizeof(u32);
  static const uptr kClockCount = kSize / sizeof(ClockElem);
  static const uptr kRefIdx = kTableSize - 1;
  static const uptr kBlockIdx = kTableSize - 2;

  union {
    u32 table[kTableSize];
    ClockElem clock[kClockCount];
  };

  ClockBlock() {}
};

const int kTidBits = 13;
// Reduce kMaxTid by kClockCount because one slot in ClockBlock table is
// occupied by reference counter, so total number of elements we can store
// in SyncClock is kClockCount * (kTableSize - 1).
const unsigned kMaxTid = (1 << kTidBits) - ClockBlock::kClockCount;
#if !SANITIZER_GO
const unsigned kMaxTidInClock = kMaxTid * 2;  // This includes msb 'freed' bit.
#else
const unsigned kMaxTidInClock = kMaxTid;  // Go does not track freed memory.
#endif
const uptr kShadowStackSize = 64 * 1024;

// Count of shadow values in a shadow cell.
const uptr kShadowCnt = 4;

// That many user bytes are mapped onto a single shadow cell.
const uptr kShadowCell = 8;

// Size of a single shadow value (u64).
const uptr kShadowSize = 8;

// Shadow memory is kShadowMultiplier times larger than user memory.
const uptr kShadowMultiplier = kShadowSize * kShadowCnt / kShadowCell;

// That many user bytes are mapped onto a single meta shadow cell.
// Must be less or equal to minimal memory allocator alignment.
const uptr kMetaShadowCell = 8;

// Size of a single meta shadow value (u32).
const uptr kMetaShadowSize = 4;

#if TREC_NO_HISTORY
const bool kCollectHistory = false;
#else
const bool kCollectHistory = true;
#endif

const u16 kInvalidTid = kMaxTid + 1;

// The following "build consistency" machinery ensures that all source files
// are built in the same configuration. Inconsistent builds lead to
// hard to debug crashes.
#if SANITIZER_DEBUG
void build_consistency_debug();
#else
void build_consistency_release();
#endif

#if TREC_COLLECT_STATS
void build_consistency_stats();
#else
void build_consistency_nostats();
#endif

static inline void USED build_consistency() {
#if SANITIZER_DEBUG
  build_consistency_debug();
#else
  build_consistency_release();
#endif
#if TREC_COLLECT_STATS
  build_consistency_stats();
#else
  build_consistency_nostats();
#endif
}

template <typename T>
T min(T a, T b) {
  return a < b ? a : b;
}

template <typename T>
T max(T a, T b) {
  return a > b ? a : b;
}

template <typename T>
T RoundUp(T p, u64 align) {
  DCHECK_EQ(align & (align - 1), 0);
  return (T)(((u64)p + align - 1) & ~(align - 1));
}

template <typename T>
T RoundDown(T p, u64 align) {
  DCHECK_EQ(align & (align - 1), 0);
  return (T)((u64)p & ~(align - 1));
}

// Zeroizes high part, returns 'bits' lsb bits.
template <typename T>
T GetLsb(T v, int bits) {
  return (T)((u64)v & ((1ull << bits) - 1));
}

struct MD5Hash {
  u64 hash[2];
  bool operator==(const MD5Hash &other) const;
};

MD5Hash md5_hash(const void *data, uptr size);

struct Processor;
struct ThreadState;
class ThreadContext;
struct Context;
struct ReportStack;
class ReportDesc;
class RegionAlloc;

// Descriptor of user's memory block.
struct MBlock {
  u64 siz : 48;
  u64 tag : 16;
  u32 stk;
  u16 tid;
};

COMPILER_CHECK(sizeof(MBlock) == 16);

enum ExternalTag : uptr {
  kExternalTagNone = 0,
  kExternalTagSwiftModifyingAccess = 1,
  kExternalTagFirstUserAvailable = 2,
  kExternalTagMax = 1024,
  // Don't set kExternalTagMax over 65,536, since MBlock only stores tags
  // as 16-bit values, see trec_defs.h.
};

}  // namespace __trec

namespace __trec_trace {
enum EventType : __sanitizer::u64 {
  ThreadBegin,
  ThreadEnd,
  PlainRead,
  PlainWrite,
  PtrRead,
  PtrWrite,
  Branch,
  FuncEnter,
  FuncExit,
  FuncParam,
  ThreadCreate,
  ThreadJoin,
  MutexLock,
  MutexUnlock,
  MemAlloc,
  MemFree,
  FuncEnterOrder,
  FuncExitParam,
  None,
  EventTypeSize,
};
static_assert(EventType::EventTypeSize < 256,
              "ERROR: EventType::EventTypeSize >= 256");
struct Event {
  EventType type : 8;
  __sanitizer::u64 : 8;  // not used
  __sanitizer::u64 gid : 48;
  __sanitizer::u64 offset : 64;
  Event(EventType _type, __sanitizer::u64 _gid, __sanitizer::u64 _offset)
      : type(_type), gid(_gid), offset(_offset) {}
};
static_assert(sizeof(Event) == 16, "ERROR: sizeof(Event) != 16");
}  // namespace __trec_trace

namespace __trec_metadata {
struct SourceAddressInfo {
  __sanitizer::u64 addr : 48;  // source variable's address, zero if not exist
  __sanitizer::u64 idx : 16;   // source variable's index in function call
                               // parameters, start from 1, zero if not exist
  SourceAddressInfo(void *_addr = 0, char _idx = 0)
      : addr((__sanitizer::u64)_addr), idx((__sanitizer::u64)_idx) {}
};
static_assert(sizeof(SourceAddressInfo) == 8,
              "ERROR: sizeof(SourceAddressInfo)!=8");
struct ReadMeta {
  __sanitizer::u64 addr;
  __sanitizer::u64 val;
  __sanitizer::u64 pc;
  __sanitizer::u64 src_idx : 16;
  __sanitizer::u64 src_addr : 48;
  ReadMeta(__sanitizer::u64 a, __sanitizer::u64 v, __sanitizer::u64 p,
           __sanitizer::u64 si, __sanitizer::u64 sa)
      : addr(a), val(v), pc(p), src_idx(si), src_addr(sa) {}
};
static_assert(sizeof(ReadMeta) == 32, "ERROR: sizeof(ReadMeta)!=32");
struct WriteMeta {
  __sanitizer::u64 addr;
  __sanitizer::u64 val;
  __sanitizer::u64 pc;
  __sanitizer::u64 addr_src_idx : 16;
  __sanitizer::u64 addr_src_addr : 48;
  __sanitizer::u64 val_src_idx : 16;
  __sanitizer::u64 val_src_addr : 48;
  WriteMeta(__sanitizer::u64 a, __sanitizer::u64 v, __sanitizer::u64 p,
            __sanitizer::u64 asi, __sanitizer::u64 asa, __sanitizer::u64 vsi,
            __sanitizer::u64 vsa)
      : addr(a),
        val(v),
        pc(p),
        addr_src_idx(asi),
        addr_src_addr(asa),
        val_src_idx(vsi),
        val_src_addr(vsa) {}
};
static_assert(sizeof(WriteMeta) == 40, "ERROR: sizeof(WriteMeta)!=40");
struct FuncParamMeta {
  __sanitizer::u64 idx : 8;
  __sanitizer::u64 src_idx : 8;
  __sanitizer::u64 src_addr : 48;
  FuncParamMeta(__sanitizer::u64 i, __sanitizer::u64 si, __sanitizer::u64 sa)
      : idx(i), src_idx(si), src_addr(sa) {}
};
static_assert(sizeof(FuncParamMeta) == 8, "ERROR: sizeof(FuncParamMeta)!=8");

struct FuncExitParamMeta {
  __sanitizer::u64 none : 8;
  __sanitizer::u64 src_idx : 8;
  __sanitizer::u64 src_addr : 48;
  FuncExitParamMeta(__sanitizer::u64 idx, __sanitizer::u64 addr)
      : none(0), src_idx(idx), src_addr(addr) {}
};
static_assert(sizeof(FuncExitParamMeta) == 8,
              "ERROR: sizeof(FuncExitParamMeta)!=8");

struct FuncEnterOrderMeta {
  __sanitizer::u64 order;
  FuncEnterOrderMeta(unsigned o) : order(o) {}
};
static_assert(sizeof(FuncEnterOrderMeta) == 8,
              "ERROR: sizeof(FuncEnterOrderMeta)!=8");

struct ThreadCreateJoinMeta {
  __sanitizer::u64 tid : 16;
  __sanitizer::u64 pc : 48;
  ThreadCreateJoinMeta(__sanitizer::u64 t, __sanitizer::u64 p)
      : tid(t), pc(p) {}
};
static_assert(sizeof(ThreadCreateJoinMeta) == 8,
              "ERROR: sizeof(ThreadCreateJoinMeta)!=8");
struct MutexMeta {
  __sanitizer::u64 lock;
  __sanitizer::u64 pc;
  __sanitizer::u64 src_idx : 8;
  __sanitizer::u64 src_addr : 48;
  MutexMeta(__sanitizer::u64 l, __sanitizer::u64 p)
      : lock(l), pc(p), src_idx(0), src_addr(0) {}
};
static_assert(sizeof(MutexMeta) == 24, "ERROR: sizeof(MutexMeta)!=16");

struct MemAllocMeta {
  __sanitizer::u64 size;
  __sanitizer::u64 addr;
  __sanitizer::u64 pc;
  MemAllocMeta(__sanitizer::u64 sz, __sanitizer::u64 a, unsigned p)
      : size(sz), addr(a), pc(p) {}
};
static_assert(sizeof(MemAllocMeta) == 24, "ERROR: sizeof(MemAllocMeta) != 24");

struct MemFreeMeta {
  __sanitizer::u64 size;
  __sanitizer::u64 addr;
  __sanitizer::u64 src_idx : 16;
  __sanitizer::u64 src_addr : 48;
  __sanitizer::u64 pc;
  MemFreeMeta(__sanitizer::u64 sz, __sanitizer::u64 a, __sanitizer::u64 si,
              __sanitizer::u64 sa, __sanitizer::u64 p)
      : size(sz), addr(a), src_idx(si), src_addr(sa), pc(p) {}
};

static_assert(sizeof(MemFreeMeta) == 32, "ERROR: sizeof(MemFreeMeta) != 32");
}  // namespace __trec_metadata

namespace __trec_header {
enum RecordType : __sanitizer::u32 {
  // Event type count
  PlainRead,
  PlainWrite,
  PtrRead,
  PtrWrite,
  ThreadCreate,
  ThreadJoin,
  FuncEnter,
  FuncExit,
  FuncParam,
  Branch,
  MemAlloc,
  MemFree,
  MutexLock,
  MutexUnlock,
  EventTypeCnt,

  // trace information
  Tid,
  TotalEventCnt,
  MetadataFileLen,
  ProcessFork,

  RecordTypeCnt,
};

struct TraceHeader {
  __sanitizer::u64 state[RecordType::RecordTypeCnt];
  char binary_path[512];
  TraceHeader(__sanitizer::u32 tid) {
    __sanitizer::internal_memset(state, 0, sizeof(state));
    state[RecordType::Tid] = tid;
    __sanitizer::internal_memset(binary_path, 0, sizeof(binary_path));
  }
  void StateInc(RecordType type) { state[type] += 1; }
};
}  // namespace __trec_header
#endif  // TREC_DEFS_H
