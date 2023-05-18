; ModuleID = 'probe5.9c762dd9-cgu.0'
source_filename = "probe5.9c762dd9-cgu.0"
target datalayout = "e-m:o-i64:64-i128:128-n32:64-S128"
target triple = "arm64-apple-macosx11.0.0"

@alloc_f0424ebc3d22f49e1e510f82279a0e19 = private unnamed_addr constant <{ [75 x i8] }> <{ [75 x i8] c"/rustc/478cbb42b730ba4739351b72ce2aa928e78e2f81/library/core/src/num/mod.rs" }>, align 1
@alloc_fad4694a37b236923f0c18a03c0fe2aa = private unnamed_addr constant <{ ptr, [16 x i8] }> <{ ptr @alloc_f0424ebc3d22f49e1e510f82279a0e19, [16 x i8] c"K\00\00\00\00\00\00\00/\04\00\00\05\00\00\00" }>, align 8
@str.0 = internal constant [25 x i8] c"attempt to divide by zero"

; probe5::probe
; Function Attrs: uwtable
define void @_ZN6probe55probe17h070d01ab62e99b5eE() unnamed_addr #0 {
start:
  %0 = call i1 @llvm.expect.i1(i1 false, i1 false)
  br i1 %0, label %panic.i, label %"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17hcce06274fec4d9b5E.exit"

panic.i:                                          ; preds = %start
; call core::panicking::panic
  call void @_ZN4core9panicking5panic17h6f64a16f410fc9ebE(ptr align 1 @str.0, i64 25, ptr align 8 @alloc_fad4694a37b236923f0c18a03c0fe2aa) #3
  unreachable

"_ZN4core3num21_$LT$impl$u20$u32$GT$10div_euclid17hcce06274fec4d9b5E.exit": ; preds = %start
  ret void
}

; Function Attrs: nocallback nofree nosync nounwind willreturn memory(none)
declare i1 @llvm.expect.i1(i1, i1) #1

; core::panicking::panic
; Function Attrs: cold noinline noreturn uwtable
declare void @_ZN4core9panicking5panic17h6f64a16f410fc9ebE(ptr align 1, i64, ptr align 8) unnamed_addr #2

attributes #0 = { uwtable "frame-pointer"="non-leaf" "target-cpu"="apple-a14" }
attributes #1 = { nocallback nofree nosync nounwind willreturn memory(none) }
attributes #2 = { cold noinline noreturn uwtable "frame-pointer"="non-leaf" "target-cpu"="apple-a14" }
attributes #3 = { noreturn }

!llvm.module.flags = !{!0}

!0 = !{i32 8, !"PIC Level", i32 2}
