; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=i686-- -mattr=-sse2 | FileCheck %s

define void @test() {
; CHECK-LABEL: test:
; CHECK:       # %bb.0:
; CHECK-NEXT:    lock orl $0, (%esp)
; CHECK-NEXT:    retl
	fence seq_cst
	ret void
}
