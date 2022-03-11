//===-- trec_mutex.h --------------------------------------------*- C++ -*-===//
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
#ifndef TREC_MUTEX_H
#define TREC_MUTEX_H

#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_mutex.h"
#include "trec_defs.h"

namespace __trec {

enum MutexType {
  MutexTypeInvalid,
  MutexTypeTrace,
  MutexTypeThreads,
  MutexTypeReport,
  MutexTypeSyncVar,
  MutexTypeSyncTab,
  MutexTypeSlab,
  MutexTypeAnnotations,
  MutexTypeAtExit,
  MutexTypeMBlock,
  MutexTypeJavaMBlock,
  MutexTypeDDetector,
  MutexTypeFired,
  MutexTypeRacy,
  MutexTypeGlobalProc,

  // This must be the last.
  MutexTypeCount
};

class Mutex {
 public:
  explicit Mutex(MutexType type, StatType stat_type);
  ~Mutex();

  void Lock();
  void Unlock();

  void ReadLock();
  void ReadUnlock();

  void CheckLocked();

 private:
  atomic_uintptr_t state_;
#if SANITIZER_DEBUG
  MutexType type_;
#endif
#if TREC_COLLECT_STATS
  StatType stat_type_;
#endif

  Mutex(const Mutex&);
  void operator = (const Mutex&);
};

typedef GenericScopedLock<Mutex> Lock;
typedef GenericScopedReadLock<Mutex> ReadLock;

class InternalDeadlockDetector {
 public:
  InternalDeadlockDetector();
  void Lock(MutexType t);
  void Unlock(MutexType t);
  void CheckNoLocks();
 private:
  u64 seq_;
  u64 locked_[MutexTypeCount];
};

void InitializeMutex();

// Checks that the current thread does not hold any runtime locks
// (e.g. when returning from an interceptor).
void CheckNoLocks(ThreadState *thr);

}  // namespace __trec

#endif  // TREC_MUTEX_H
