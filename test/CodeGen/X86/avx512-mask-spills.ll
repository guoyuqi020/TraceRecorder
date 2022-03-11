; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-apple-darwin -mcpu=skx | FileCheck %s

declare void @f()
define <4 x i1> @test_4i1(<4 x i32> %a, <4 x i32> %b) {
; CHECK-LABEL: test_4i1:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    pushq %rax
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    vpcmpnleud %xmm1, %xmm0, %k0
; CHECK-NEXT:    vpcmpgtd %xmm1, %xmm0, %k1
; CHECK-NEXT:    korw %k1, %k0, %k0
; CHECK-NEXT:    kmovw %k0, {{[-0-9]+}}(%r{{[sb]}}p) ## 2-byte Spill
; CHECK-NEXT:    callq _f
; CHECK-NEXT:    kmovw {{[-0-9]+}}(%r{{[sb]}}p), %k0 ## 2-byte Reload
; CHECK-NEXT:    vpmovm2d %k0, %xmm0
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    retq

  %cmp_res = icmp ugt <4 x i32> %a, %b
  %cmp_res2 = icmp sgt <4 x i32> %a, %b
  call void @f()
  %res = or <4 x i1> %cmp_res, %cmp_res2
  ret <4 x i1> %res
}

define <8 x i1> @test_8i1(<8 x i32> %a, <8 x i32> %b) {
; CHECK-LABEL: test_8i1:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    pushq %rax
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    vpcmpnleud %ymm1, %ymm0, %k0
; CHECK-NEXT:    vpcmpgtd %ymm1, %ymm0, %k1
; CHECK-NEXT:    korb %k1, %k0, %k0
; CHECK-NEXT:    kmovw %k0, {{[-0-9]+}}(%r{{[sb]}}p) ## 2-byte Spill
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    callq _f
; CHECK-NEXT:    kmovw {{[-0-9]+}}(%r{{[sb]}}p), %k0 ## 2-byte Reload
; CHECK-NEXT:    vpmovm2w %k0, %xmm0
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    retq

  %cmp_res = icmp ugt <8 x i32> %a, %b
  %cmp_res2 = icmp sgt <8 x i32> %a, %b
  call void @f()
  %res = or <8 x i1> %cmp_res, %cmp_res2
  ret <8 x i1> %res
}

define <16 x i1> @test_16i1(<16 x i32> %a, <16 x i32> %b) {
; CHECK-LABEL: test_16i1:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    pushq %rax
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    vpcmpnleud %zmm1, %zmm0, %k0
; CHECK-NEXT:    vpcmpgtd %zmm1, %zmm0, %k1
; CHECK-NEXT:    korw %k1, %k0, %k0
; CHECK-NEXT:    kmovw %k0, {{[-0-9]+}}(%r{{[sb]}}p) ## 2-byte Spill
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    callq _f
; CHECK-NEXT:    kmovw {{[-0-9]+}}(%r{{[sb]}}p), %k0 ## 2-byte Reload
; CHECK-NEXT:    vpmovm2b %k0, %xmm0
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    retq
  %cmp_res = icmp ugt <16 x i32> %a, %b
  %cmp_res2 = icmp sgt <16 x i32> %a, %b
  call void @f()
  %res = or <16 x i1> %cmp_res, %cmp_res2
  ret <16 x i1> %res
}

define <32 x i1> @test_32i1(<32 x i16> %a, <32 x i16> %b) {
; CHECK-LABEL: test_32i1:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    pushq %rax
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    vpcmpnleuw %zmm1, %zmm0, %k0
; CHECK-NEXT:    vpcmpgtw %zmm1, %zmm0, %k1
; CHECK-NEXT:    kord %k1, %k0, %k0
; CHECK-NEXT:    kmovd %k0, {{[-0-9]+}}(%r{{[sb]}}p) ## 4-byte Spill
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    callq _f
; CHECK-NEXT:    kmovd {{[-0-9]+}}(%r{{[sb]}}p), %k0 ## 4-byte Reload
; CHECK-NEXT:    vpmovm2b %k0, %ymm0
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    retq
  %cmp_res = icmp ugt <32 x i16> %a, %b
  %cmp_res2 = icmp sgt <32 x i16> %a, %b
  call void @f()
  %res = or <32 x i1> %cmp_res, %cmp_res2
  ret <32 x i1> %res
}

define <64 x i1> @test_64i1(<64 x i8> %a, <64 x i8> %b) {
; CHECK-LABEL: test_64i1:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    pushq %rax
; CHECK-NEXT:    .cfi_def_cfa_offset 16
; CHECK-NEXT:    vpcmpnleub %zmm1, %zmm0, %k0
; CHECK-NEXT:    vpcmpgtb %zmm1, %zmm0, %k1
; CHECK-NEXT:    korq %k1, %k0, %k0
; CHECK-NEXT:    kmovq %k0, (%rsp) ## 8-byte Spill
; CHECK-NEXT:    vzeroupper
; CHECK-NEXT:    callq _f
; CHECK-NEXT:    kmovq (%rsp), %k0 ## 8-byte Reload
; CHECK-NEXT:    vpmovm2b %k0, %zmm0
; CHECK-NEXT:    popq %rax
; CHECK-NEXT:    retq

  %cmp_res = icmp ugt <64 x i8> %a, %b
  %cmp_res2 = icmp sgt <64 x i8> %a, %b
  call void @f()
  %res = or <64 x i1> %cmp_res, %cmp_res2
  ret <64 x i1> %res
}
