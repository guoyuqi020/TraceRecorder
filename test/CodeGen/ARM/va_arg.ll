; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=armv7-none-linux-gnueabi -pre-RA-sched=source | FileCheck %s
; Test that we correctly align elements when using va_arg

define i64 @test1(i32 %i, ...) nounwind optsize {
; CHECK-LABEL: test1:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    .pad #12
; CHECK-NEXT:    sub sp, sp, #12
; CHECK-NEXT:    .pad #4
; CHECK-NEXT:    sub sp, sp, #4
; CHECK-NEXT:    add r0, sp, #4
; CHECK-NEXT:    stmib sp, {r1, r2, r3}
; CHECK-NEXT:    add r0, r0, #7
; CHECK-NEXT:    bic r1, r0, #7
; CHECK-NEXT:    orr r0, r1, #4
; CHECK-NEXT:    str r0, [sp]
; CHECK-NEXT:    ldr r0, [r1]
; CHECK-NEXT:    add r2, r1, #8
; CHECK-NEXT:    str r2, [sp]
; CHECK-NEXT:    ldr r1, [r1, #4]
; CHECK-NEXT:    add sp, sp, #4
; CHECK-NEXT:    add sp, sp, #12
; CHECK-NEXT:    bx lr
entry:
  %g = alloca i8*, align 4
  %g1 = bitcast i8** %g to i8*
  call void @llvm.va_start(i8* %g1)
  %0 = va_arg i8** %g, i64
  call void @llvm.va_end(i8* %g1)
  ret i64 %0
}

define double @test2(i32 %a, i32* %b, ...) nounwind optsize {
; CHECK-LABEL: test2:
; CHECK:       @ %bb.0: @ %entry
; CHECK-NEXT:    .pad #8
; CHECK-NEXT:    sub sp, sp, #8
; CHECK-NEXT:    .pad #4
; CHECK-NEXT:    sub sp, sp, #4
; CHECK-NEXT:    add r0, sp, #4
; CHECK-NEXT:    stmib sp, {r2, r3}
; CHECK-NEXT:    add r0, r0, #11
; CHECK-NEXT:    bic r0, r0, #3
; CHECK-NEXT:    str r2, [r1]
; CHECK-NEXT:    add r1, r0, #8
; CHECK-NEXT:    str r1, [sp]
; CHECK-NEXT:    vldr d16, [r0]
; CHECK-NEXT:    vmov r0, r1, d16
; CHECK-NEXT:    add sp, sp, #4
; CHECK-NEXT:    add sp, sp, #8
; CHECK-NEXT:    bx lr
entry:
  %ap = alloca i8*, align 4                       ; <i8**> [#uses=3]
  %ap1 = bitcast i8** %ap to i8*                  ; <i8*> [#uses=2]
  call void @llvm.va_start(i8* %ap1)
  %0 = va_arg i8** %ap, i32                       ; <i32> [#uses=0]
  store i32 %0, i32* %b
  %1 = va_arg i8** %ap, double                    ; <double> [#uses=1]
  call void @llvm.va_end(i8* %ap1)
  ret double %1
}


declare void @llvm.va_start(i8*) nounwind

declare void @llvm.va_end(i8*) nounwind
