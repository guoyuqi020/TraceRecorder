//===-- trec_symbolize.h ----------------------------------------*- C++ -*-===//
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
#ifndef TREC_SYMBOLIZE_H
#define TREC_SYMBOLIZE_H

#include "trec_defs.h"
#include "trec_report.h"

namespace __trec {

void EnterSymbolizer();
void ExitSymbolizer();
SymbolizedStack *SymbolizeCode(uptr addr);
ReportLocation *SymbolizeData(uptr addr);
void SymbolizeFlush();

ReportStack *NewReportStackEntry(uptr addr);

}  // namespace __trec

#endif  // TREC_SYMBOLIZE_H
