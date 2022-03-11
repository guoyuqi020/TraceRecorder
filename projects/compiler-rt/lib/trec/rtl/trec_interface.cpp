//===-- trec_interface.cpp
//------------------------------------------------===//
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

#include "trec_interface.h"

#include "sanitizer_common/sanitizer_internal_defs.h"
#include "sanitizer_common/sanitizer_ptrauth.h"
#include "trec_interface_ann.h"
#include "trec_rtl.h"

#define CALLERPC ((uptr)__builtin_return_address(0))

using namespace __trec;
using namespace __trec_metadata;

void __trec_init() {
  cur_thread_init();
  Initialize(cur_thread());
}

void __trec_flush_memory() { FlushShadowMemory(); }

#define GET_128_HIGHHER(x) (uptr)(x >> 64)
#define GET_128_LOWER(x) (uptr)(x)
void __trec_read16(void *addr, bool isPtr, __uint128_t val, void *addr_src_addr,
                   char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr, kSizeLog8, isPtr,
             GET_128_LOWER(val), SAI_addr);
  MemoryRead(cur_thread(), CALLERPC, (uptr)addr + 8, kSizeLog8, isPtr,
             GET_128_HIGHHER(val), SAI_addr);
}

void __trec_write16(void *addr, bool isPtr, __uint128_t val,
                    void *addr_src_addr, char addr_src_idx, void *val_src_addr,
                    char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr, kSizeLog8, isPtr,
              GET_128_LOWER(val), SAI_addr, SAI_val);
  MemoryWrite(cur_thread(), CALLERPC, (uptr)addr + 8, kSizeLog8, isPtr,
              GET_128_HIGHHER(val), SAI_addr, SAI_val);
}

// __trec_unaligned_read/write calls are emitted by compiler.

void __trec_unaligned_read2(const void *addr, bool isPtr, void *val,
                            void *addr_src_addr, char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 2, false, false,
                        isPtr, (uptr)val, SAI_addr);
}

void __trec_unaligned_read4(const void *addr, bool isPtr, void *val,
                            void *addr_src_addr, char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 4, false, false,
                        isPtr, (uptr)val, SAI_addr);
}

void __trec_unaligned_read8(const void *addr, bool isPtr, void *val,
                            void *addr_src_addr, char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, false, false,
                        isPtr, (uptr)val, SAI_addr);
}

void __trec_unaligned_read16(const void *addr, bool isPtr, __uint128_t val,
                             void *addr_src_addr, char addr_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, false, false,
                        isPtr, GET_128_LOWER(val), SAI_addr);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr + 8, 8, false, false,
                        isPtr, GET_128_HIGHHER(val), SAI_addr);
}

void __trec_unaligned_write2(void *addr, bool isPtr, void *val,
                             void *addr_src_addr, char addr_src_idx,
                             void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 2, true, false,
                        isPtr, (uptr)val, SAI_addr, SAI_val);
}

void __trec_unaligned_write4(void *addr, bool isPtr, void *val,
                             void *addr_src_addr, char addr_src_idx,
                             void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 4, true, false,
                        isPtr, (uptr)val, SAI_addr, SAI_val);
}

void __trec_unaligned_write8(void *addr, bool isPtr, void *val,
                             void *addr_src_addr, char addr_src_idx,
                             void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, true, false,
                        isPtr, (uptr)val, SAI_addr, SAI_val);
}

void __trec_unaligned_write16(void *addr, bool isPtr, __uint128_t val,
                              void *addr_src_addr, char addr_src_idx,
                              void *val_src_addr, char val_src_idx) {
  SourceAddressInfo SAI_addr(addr_src_addr, addr_src_idx);
  SourceAddressInfo SAI_val(val_src_addr, val_src_idx);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr, 8, true, false,
                        isPtr, GET_128_LOWER(val), SAI_addr, SAI_val);
  UnalignedMemoryAccess(cur_thread(), CALLERPC, (uptr)addr + 8, 8, true, false,
                        isPtr, GET_128_HIGHHER(val), SAI_addr, SAI_val);
}

#undef GET_128_HIGHHER
#undef GET_128_LOWER
// __sanitizer_unaligned_load/store are for user instrumentation.

extern "C" {
SANITIZER_INTERFACE_ATTRIBUTE
u16 __sanitizer_unaligned_load16(const uu16 *addr) {
  __trec_unaligned_read2(addr, false, 0, 0, 0);
  return *addr;
}

SANITIZER_INTERFACE_ATTRIBUTE
u32 __sanitizer_unaligned_load32(const uu32 *addr) {
  __trec_unaligned_read4(addr, false, 0, 0, 0);
  return *addr;
}

SANITIZER_INTERFACE_ATTRIBUTE
u64 __sanitizer_unaligned_load64(const uu64 *addr) {
  __trec_unaligned_read8(addr, false, 0, 0, 0);
  return *addr;
}

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store16(uu16 *addr, u16 v) {
  __trec_unaligned_write2(addr, false, 0, 0, 0, 0, 0);
  *addr = v;
}

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store32(uu32 *addr, u32 v) {
  __trec_unaligned_write4(addr, false, 0, 0, 0, 0, 0);
  *addr = v;
}

SANITIZER_INTERFACE_ATTRIBUTE
void __sanitizer_unaligned_store64(uu64 *addr, u64 v) {
  __trec_unaligned_write8(addr, false, 0, 0, 0, 0, 0);
  *addr = v;
}

SANITIZER_INTERFACE_ATTRIBUTE
void *__trec_get_current_fiber() { return cur_thread(); }

SANITIZER_INTERFACE_ATTRIBUTE
void *__trec_create_fiber(unsigned flags) {
  return FiberCreate(cur_thread(), CALLERPC, flags);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __trec_destroy_fiber(void *fiber) {
  FiberDestroy(cur_thread(), CALLERPC, static_cast<ThreadState *>(fiber));
}

SANITIZER_INTERFACE_ATTRIBUTE
void __trec_switch_to_fiber(void *fiber, unsigned flags) {
  FiberSwitch(cur_thread(), CALLERPC, static_cast<ThreadState *>(fiber), flags);
}

SANITIZER_INTERFACE_ATTRIBUTE
void __trec_set_fiber_name(void *fiber, const char *name) {
  ThreadSetName(static_cast<ThreadState *>(fiber), name);
}
}  // extern "C"

void __trec_acquire(void *addr) { Acquire(cur_thread(), CALLERPC, (uptr)addr); }

void __trec_release(void *addr) { Release(cur_thread(), CALLERPC, (uptr)addr); }
