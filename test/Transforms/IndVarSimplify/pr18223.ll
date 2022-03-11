; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -indvars -S < %s | FileCheck %s

; indvars should transform the phi node pair from the for-loop

@c = common global i32 0, align 4

define i32 @main() #0 {
; CHECK-LABEL: @main(
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = load i32, i32* @c, align 4
; CHECK-NEXT:    [[TOBOOL:%.*]] = icmp eq i32 [[TMP0]], 0
; CHECK-NEXT:    br i1 [[TOBOOL]], label [[FOR_BODY_PREHEADER:%.*]], label [[EXIT:%.*]]
; CHECK:       for.body.preheader:
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    br label [[FOR_INC:%.*]]
; CHECK:       for.inc:
; CHECK-NEXT:    br i1 false, label [[FOR_BODY]], label [[EXIT_LOOPEXIT:%.*]]
; CHECK:       exit.loopexit:
; CHECK-NEXT:    br label [[EXIT]]
; CHECK:       exit:
; CHECK-NEXT:    [[RET:%.*]] = phi i32 [ 0, [[ENTRY:%.*]] ], [ 0, [[EXIT_LOOPEXIT]] ]
; CHECK-NEXT:    ret i32 [[RET]]
;
entry:
  %0 = load i32, i32* @c, align 4
  %tobool = icmp eq i32 %0, 0
  br i1 %tobool, label %for.body, label %exit

for.body:
  %inc2 = phi i32 [ 0, %entry ], [ %inc, %for.inc ]
  %sub = add i32 %inc2, -1
  %cmp1 = icmp uge i32 %sub, %inc2
  %conv = zext i1 %cmp1 to i32
  br label %for.inc

for.inc:
  %inc = add nsw i32 %inc2, 1
  %cmp = icmp slt i32 %inc, 5
  br i1 %cmp, label %for.body, label %exit

exit:
  %ret = phi i32 [ 0, %entry ], [ %conv, %for.inc ]
  ret i32 %ret
}
