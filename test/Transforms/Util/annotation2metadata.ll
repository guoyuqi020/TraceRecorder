; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -annotation2metadata -pass-remarks-analysis='annotation-remarks' -S %s | FileCheck %s
; RUN: opt -passes='annotation2metadata' -pass-remarks-analysis='annotation-remarks' -S %s | FileCheck %s

@.str = private unnamed_addr constant [10 x i8] c"_remarks1\00", section "llvm.metadata"
@.str.1 = private unnamed_addr constant [6 x i8] c"ann.c\00", section "llvm.metadata"
@.str.2 = private unnamed_addr constant [10 x i8] c"_remarks2\00", section "llvm.metadata"
@llvm.global.annotations = appending global [8 x { i8*, i8*, i8*, i32 }] [
    { i8*, i8*, i8*, i32 } { i8* bitcast (void (float*)* @test1 to i8*), i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), i32 2 },
    { i8*, i8*, i8*, i32 } { i8* bitcast (void (float*)* @test1 to i8*), i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str.2, i32 0, i32 0), i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), i32 2 },
    { i8*, i8*, i8*, i32 } { i8* bitcast (void (float*)* @test3 to i8*), i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* undef, i32 4 }, ; Invalid entry, make sure we do not crash.
    { i8*, i8*, i8*, i32 } { i8* bitcast (void (float*)* @test3 to i8*), i8* undef, i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), i32 4 }, ; Invalid entry, make sure we do not crash.
    { i8*, i8*, i8*, i32 } { i8* undef, i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), i32 4 }, ; Invalid entry, make sure we do not crash.
    { i8*, i8*, i8*, i32 } { i8* bitcast (void (float*)* undef to i8*), i8* undef, i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), i32 4 }, ; Invalid entry, make sure we do not crash.
    { i8*, i8*, i8*, i32 } { i8* undef, i8* undef, i8* undef, i32 300 },  ; Invalid entry, make sure we do not crash.
    { i8*, i8*, i8*, i32 } { i8* bitcast (void (float*)* @test3 to i8*), i8* getelementptr inbounds ([10 x i8], [10 x i8]* @.str, i32 0, i32 0), i8* getelementptr inbounds ([6 x i8], [6 x i8]* @.str.1, i32 0, i32 0), i32 4 }
    ], section "llvm.metadata"



define void @test1(float* %a) {
; CHECK-LABEL: @test1(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_ADDR:%.*]] = alloca float*, align 8, !annotation [[GROUP1:!.+]]
; CHECK-NEXT:    store float* [[A:%.*]], float** [[A_ADDR]], align 8, !annotation [[GROUP1]]
; CHECK-NEXT:    ret void, !annotation [[GROUP1]]
;
entry:
  %a.addr = alloca float*, align 8
  store float* %a, float** %a.addr, align 8
  ret void
}

define void @test2(float* %a) {
; CHECK-LABEL: @test2(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_ADDR:%.*]] = alloca float*, align 8
; CHECK-NEXT:    store float* [[A:%.*]], float** [[A_ADDR]], align 8
; CHECK-NEXT:    ret void
;
entry:
  %a.addr = alloca float*, align 8
  store float* %a, float** %a.addr, align 8
  ret void
}

define void @test3(float* %a) {
; CHECK-LABEL: @test3(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[A_ADDR:%.*]] = alloca float*, align 8, !annotation [[GROUP2:!.+]]
; CHECK-NEXT:    store float* [[A:%.*]], float** [[A_ADDR]], align 8, !annotation [[GROUP2]]
; CHECK-NEXT:    ret void, !annotation [[GROUP2]]
;
entry:
  %a.addr = alloca float*, align 8
  store float* %a, float** %a.addr, align 8
  ret void
}

; CHECK:      [[GROUP1]] = !{!"_remarks1", !"_remarks2"}
; CHECK-NEXT: [[GROUP2]] = !{!"_remarks1"}
