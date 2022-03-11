//===-- trec_platform_windows.cpp -----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of TraceRecorder (TRec), a race detector.
//
// Windows-specific code.
//===----------------------------------------------------------------------===//

#include "sanitizer_common/sanitizer_platform.h"
#if SANITIZER_WINDOWS

#include "trec_platform.h"

#include <stdlib.h>

namespace __trec {

void FlushShadowMemory() {
}

void WriteMemoryProfile(char *buf, uptr buf_size, uptr nthread, uptr nlive) {
}

void InitializePlatformEarly() {
}

void InitializePlatform() {
}

}  // namespace __trec

#endif  // SANITIZER_WINDOWS