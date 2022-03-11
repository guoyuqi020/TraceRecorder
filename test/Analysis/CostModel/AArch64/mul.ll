; NOTE: Assertions have been autogenerated by utils/update_analyze_test_checks.py
; RUN: opt < %s -mtriple=aarch64-unknown-linux-gnu -cost-model -cost-kind=throughput -analyze | FileCheck %s --check-prefix=THROUGHPUT

; Verify the cost of (vector) multiply instructions.

define <2 x i8> @t1(<2 x i8> %a, <2 x i8> %b)  {
; THROUGHPUT-LABEL: 't1'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <2 x i8> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x i8> %1
;
  %1 = mul <2 x i8> %a, %b
  ret <2 x i8> %1
}

define <4 x i8> @t2(<4 x i8> %a, <4 x i8> %b)  {
; THROUGHPUT-LABEL: 't2'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <4 x i8> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x i8> %1
;
  %1 = mul <4 x i8> %a, %b
  ret <4 x i8> %1
}

define <8 x i8> @t3(<8 x i8> %a, <8 x i8> %b)  {
; THROUGHPUT-LABEL: 't3'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <8 x i8> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <8 x i8> %1
;
  %1 = mul <8 x i8> %a, %b
  ret <8 x i8> %1
}

define <16 x i8> @t4(<16 x i8> %a, <16 x i8> %b)  {
; THROUGHPUT-LABEL: 't4'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <16 x i8> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <16 x i8> %1
;
  %1 = mul <16 x i8> %a, %b
  ret <16 x i8> %1
}

define <32 x i8> @t5(<32 x i8> %a, <32 x i8> %b)  {
; THROUGHPUT-LABEL: 't5'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = mul <32 x i8> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <32 x i8> %1
;
  %1 = mul <32 x i8> %a, %b
  ret <32 x i8> %1
}

define <2 x i16> @t6(<2 x i16> %a, <2 x i16> %b)  {
; THROUGHPUT-LABEL: 't6'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <2 x i16> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x i16> %1
;
  %1 = mul <2 x i16> %a, %b
  ret <2 x i16> %1
}

define <4 x i16> @t7(<4 x i16> %a, <4 x i16> %b)  {
; THROUGHPUT-LABEL: 't7'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <4 x i16> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x i16> %1
;
  %1 = mul <4 x i16> %a, %b
  ret <4 x i16> %1
}

define <8 x i16> @t8(<8 x i16> %a, <8 x i16> %b)  {
; THROUGHPUT-LABEL: 't8'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <8 x i16> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <8 x i16> %1
;
  %1 = mul <8 x i16> %a, %b
  ret <8 x i16> %1
}

define <16 x i16> @t9(<16 x i16> %a, <16 x i16> %b)  {
; THROUGHPUT-LABEL: 't9'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = mul <16 x i16> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <16 x i16> %1
;
  %1 = mul <16 x i16> %a, %b
  ret <16 x i16> %1
}

define <2 x i32> @t10(<2 x i32> %a, <2 x i32> %b)  {
; THROUGHPUT-LABEL: 't10'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <2 x i32> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x i32> %1
;
  %1 = mul <2 x i32> %a, %b
  ret <2 x i32> %1
}

define <4 x i32> @t11(<4 x i32> %a, <4 x i32> %b)  {
; THROUGHPUT-LABEL: 't11'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 1 for instruction: %1 = mul <4 x i32> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x i32> %1
;
  %1 = mul <4 x i32> %a, %b
  ret <4 x i32> %1
}

define <8 x i32> @t12(<8 x i32> %a, <8 x i32> %b)  {
; THROUGHPUT-LABEL: 't12'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = mul <8 x i32> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <8 x i32> %1
;
  %1 = mul <8 x i32> %a, %b
  ret <8 x i32> %1
}

define <2 x i64> @t13(<2 x i64> %a, <2 x i64> %b)  {
; THROUGHPUT-LABEL: 't13'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 8 for instruction: %1 = mul nsw <2 x i64> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x i64> %1
;
  %1 = mul nsw <2 x i64> %a, %b
  ret <2 x i64> %1
}

define <4 x i64> @t14(<4 x i64> %a, <4 x i64> %b)  {
; THROUGHPUT-LABEL: 't14'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 16 for instruction: %1 = mul nsw <4 x i64> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x i64> %1
;
  %1 = mul nsw <4 x i64> %a, %b
  ret <4 x i64> %1
}

define <2 x float> @t15(<2 x float> %a, <2 x float> %b)  {
; THROUGHPUT-LABEL: 't15'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = fmul <2 x float> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x float> %1
;
  %1 = fmul <2 x float> %a, %b
  ret <2 x float> %1
}

define <4 x float> @t16(<4 x float> %a, <4 x float> %b)  {
; THROUGHPUT-LABEL: 't16'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = fmul <4 x float> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x float> %1
;
  %1 = fmul <4 x float> %a, %b
  ret <4 x float> %1
}

define <8 x float> @t17(<8 x float> %a, <8 x float> %b)  {
; THROUGHPUT-LABEL: 't17'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 4 for instruction: %1 = fmul <8 x float> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <8 x float> %1
;
  %1 = fmul <8 x float> %a, %b
  ret <8 x float> %1
}

define <2 x half> @t18(<2 x half> %a, <2 x half> %b)  {
; THROUGHPUT-LABEL: 't18'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = fmul <2 x half> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x half> %1
;
  %1 = fmul <2 x half> %a, %b
  ret <2 x half> %1
}

define <4 x half> @t19(<4 x half> %a, <4 x half> %b)  {
; THROUGHPUT-LABEL: 't19'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = fmul <4 x half> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x half> %1
;
  %1 = fmul <4 x half> %a, %b
  ret <4 x half> %1
}

define <8 x half> @t20(<8 x half> %a, <8 x half> %b)  {
; THROUGHPUT-LABEL: 't20'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 58 for instruction: %1 = fmul <8 x half> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <8 x half> %1
;
  %1 = fmul <8 x half> %a, %b
  ret <8 x half> %1
}

define <16 x half> @t21(<16 x half> %a, <16 x half> %b)  {
; THROUGHPUT-LABEL: 't21'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 116 for instruction: %1 = fmul <16 x half> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <16 x half> %1
;
  %1 = fmul <16 x half> %a, %b
  ret <16 x half> %1
}

define <2 x double> @t22(<2 x double> %a, <2 x double> %b)  {
; THROUGHPUT-LABEL: 't22'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 2 for instruction: %1 = fmul <2 x double> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <2 x double> %1
;
  %1 = fmul <2 x double> %a, %b
  ret <2 x double> %1
}

define <4 x double> @t23(<4 x double> %a, <4 x double> %b)  {
; THROUGHPUT-LABEL: 't23'
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 4 for instruction: %1 = fmul <4 x double> %a, %b
; THROUGHPUT-NEXT:  Cost Model: Found an estimated cost of 0 for instruction: ret <4 x double> %1
;
  %1 = fmul <4 x double> %a, %b
  ret <4 x double> %1
}