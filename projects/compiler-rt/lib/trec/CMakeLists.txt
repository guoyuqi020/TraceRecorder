# Build for the ThreadSanitizer runtime support library.

include_directories(..)

set(TREC_CFLAGS ${SANITIZER_COMMON_CFLAGS})
# SANITIZER_COMMON_CFLAGS contains -fPIC, but it's performance-critical for
# Trec runtime to be built with -fPIE to reduce the number of register spills.
# On FreeBSD however it provokes linkage issue thus we disable it.
if(NOT CMAKE_SYSTEM MATCHES "FreeBSD")
  append_list_if(COMPILER_RT_HAS_FPIE_FLAG -fPIE TREC_CFLAGS)
endif()
append_rtti_flag(OFF TREC_CFLAGS)

if(COMPILER_RT_TREC_DEBUG_OUTPUT)
  # Add extra debug information to Trec runtime. This configuration is rarely
  # used, but we need to support it so that debug output will not bitrot.
  list(APPEND TREC_CFLAGS -DTREC_COLLECT_STATS=1
                          -DTREC_DEBUG_OUTPUT=2)
endif()

set(TREC_RTL_CFLAGS ${TREC_CFLAGS})
append_list_if(COMPILER_RT_HAS_MSSE3_FLAG -msse3 TREC_RTL_CFLAGS)
append_list_if(SANITIZER_LIMIT_FRAME_SIZE -Wframe-larger-than=530
               TREC_RTL_CFLAGS)
append_list_if(COMPILER_RT_HAS_WGLOBAL_CONSTRUCTORS_FLAG -Wglobal-constructors
               TREC_RTL_CFLAGS)

set(TREC_SOURCES
  rtl/trec_clock.cpp
  rtl/trec_debugging.cpp
  rtl/trec_external.cpp
  rtl/trec_fd.cpp
  rtl/trec_flags.cpp
  rtl/trec_ignoreset.cpp
  rtl/trec_interceptors_posix.cpp
  rtl/trec_interface.cpp
  rtl/trec_interface_ann.cpp
  rtl/trec_interface_atomic.cpp
  rtl/trec_interface_java.cpp
  rtl/trec_malloc_mac.cpp
  rtl/trec_md5.cpp
  rtl/trec_mman.cpp
  rtl/trec_mutex.cpp
  rtl/trec_mutexset.cpp
  rtl/trec_preinit.cpp
  rtl/trec_report.cpp
  rtl/trec_rtl.cpp
  rtl/trec_rtl_mutex.cpp
  rtl/trec_rtl_proc.cpp
  rtl/trec_rtl_report.cpp
  rtl/trec_rtl_thread.cpp
  rtl/trec_stack_trace.cpp
  rtl/trec_stat.cpp
  rtl/trec_suppressions.cpp
  rtl/trec_symbolize.cpp
  rtl/trec_sync.cpp
  )

set(TREC_CXX_SOURCES
  rtl/trec_new_delete.cpp
  )

if(APPLE)
  list(APPEND TREC_SOURCES
    rtl/trec_interceptors_mac.cpp
    rtl/trec_interceptors_mach_vm.cpp
    rtl/trec_platform_mac.cpp
    rtl/trec_platform_posix.cpp
    )
elseif(UNIX)
  # Assume Linux
  list(APPEND TREC_SOURCES
    rtl/trec_platform_linux.cpp
    rtl/trec_platform_posix.cpp
    )
endif()

if(COMPILER_RT_INTERCEPT_LIBDISPATCH)
  list(APPEND TREC_SOURCES
    rtl/trec_interceptors_libdispatch.cpp
    )
  list(APPEND TREC_RTL_CFLAGS ${COMPILER_RT_LIBDISPATCH_CFLAGS})
endif()

set(TREC_HEADERS
  rtl/trec_clock.h
  rtl/trec_defs.h
  rtl/trec_dense_alloc.h
  rtl/trec_fd.h
  rtl/trec_flags.h
  rtl/trec_flags.inc
  rtl/trec_ignoreset.h
  rtl/trec_interceptors.h
  rtl/trec_interface.h
  rtl/trec_interface_ann.h
  rtl/trec_interface_inl.h
  rtl/trec_interface_java.h
  rtl/trec_mman.h
  rtl/trec_mutex.h
  rtl/trec_mutexset.h
  rtl/trec_platform.h
  rtl/trec_ppc_regs.h
  rtl/trec_report.h
  rtl/trec_rtl.h
  rtl/trec_stack_trace.h
  rtl/trec_stat.h
  rtl/trec_suppressions.h
  rtl/trec_symbolize.h
  rtl/trec_sync.h
  rtl/trec_trace.h
  rtl/trec_update_shadow_word_inl.h)

set(TREC_RUNTIME_LIBRARIES)
add_compiler_rt_component(trec)

if(APPLE)
  # Ideally we would check the SDK version for the actual platform we are
  # building for here.  To make our lifes easier we assume the host SDK setup is
  # sane and use the macOS SDK version as a proxy for aligned SDKs.
  find_darwin_sdk_version(macosx_sdk_version "macosx")
  if ("${macosx_sdk_version}" VERSION_LESS 10.12)
    message(FATAL_ERROR "Building the Trec runtime requires at least macOS SDK 10.12 (or aligned SDK on other platforms)")
  endif()

  add_asm_sources(TREC_ASM_SOURCES rtl/trec_rtl_amd64.S rtl/trec_rtl_aarch64.S)

  set(TREC_LINK_LIBS ${SANITIZER_COMMON_LINK_LIBS})

  add_weak_symbols("ubsan" WEAK_SYMBOL_LINK_FLAGS)
  add_weak_symbols("sanitizer_common" WEAK_SYMBOL_LINK_FLAGS)

  add_compiler_rt_runtime(clang_rt.trec
    SHARED
    OS ${TREC_SUPPORTED_OS}
    ARCHS ${TREC_SUPPORTED_ARCH}
    SOURCES ${TREC_SOURCES} ${TREC_CXX_SOURCES} ${TREC_ASM_SOURCES}
    ADDITIONAL_HEADERS ${TREC_HEADERS}
    OBJECT_LIBS RTInterception
                RTSanitizerCommon
                RTSanitizerCommonLibc
                RTSanitizerCommonCoverage
                RTSanitizerCommonSymbolizer
                RTUbsan
    CFLAGS ${TREC_RTL_CFLAGS}
    LINK_FLAGS ${SANITIZER_COMMON_LINK_FLAGS} ${WEAK_SYMBOL_LINK_FLAGS}
    LINK_LIBS ${TREC_LINK_LIBS} objc
    PARENT_TARGET trec)
  add_compiler_rt_object_libraries(RTTrec_dynamic
    OS ${TREC_SUPPORTED_OS}
    ARCHS ${TREC_SUPPORTED_ARCH}
    SOURCES ${TREC_SOURCES} ${TREC_CXX_SOURCES} ${TREC_ASM_SOURCES}
    ADDITIONAL_HEADERS ${TREC_HEADERS}
    CFLAGS ${TREC_RTL_CFLAGS})

  # Build and check Go runtime.
  set(BUILDGO_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/go/buildgo.sh)
  add_custom_target(GotrecRuntimeCheck
    COMMAND env "CC=${CMAKE_C_COMPILER} ${OSX_SYSROOT_FLAG}"
            IN_TMPDIR=1 SILENT=1 ${BUILDGO_SCRIPT}
    DEPENDS trec ${BUILDGO_SCRIPT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/go
    COMMENT "Checking Trec Go runtime..."
    VERBATIM)
  set_target_properties(GotrecRuntimeCheck PROPERTIES FOLDER "Compiler-RT Misc")
else()
  foreach(arch ${TREC_SUPPORTED_ARCH})
    if(arch STREQUAL "x86_64")
      add_asm_sources(TREC_ASM_SOURCES rtl/trec_rtl_amd64.S)
      # Sanity check for Go runtime.
      set(BUILDGO_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/go/buildgo.sh)
      add_custom_target(GotrecRuntimeCheck
        COMMAND env "CC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1}"
                IN_TMPDIR=1 SILENT=1 ${BUILDGO_SCRIPT}
        DEPENDS clang_rt.trec-${arch} ${BUILDGO_SCRIPT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/go
        COMMENT "Checking Trec Go runtime..."
        VERBATIM)
    elseif(arch STREQUAL "aarch64")
      add_asm_sources(TREC_ASM_SOURCES rtl/trec_rtl_aarch64.S)
      # Sanity check for Go runtime.
      set(BUILDGO_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/go/buildgo.sh)
      add_custom_target(GotrecRuntimeCheck
	COMMAND env "CC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1}"
		IN_TMPDIR=1 SILENT=1 ${BUILDGO_SCRIPT}
	DEPENDS clang_rt.trec-${arch} ${BUILDGO_SCRIPT}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/go
	COMMENT "Checking Trec Go runtime..."
	VERBATIM)
    elseif(arch MATCHES "powerpc64|powerpc64le")
      add_asm_sources(TREC_ASM_SOURCES rtl/trec_rtl_ppc64.S)
      # Sanity check for Go runtime.
      set(BUILDGO_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/go/buildgo.sh)
      add_custom_target(GotrecRuntimeCheck
	COMMAND env "CC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_ARG1}"
		IN_TMPDIR=1 SILENT=1 ${BUILDGO_SCRIPT}
	DEPENDS clang_rt.trec-${arch} ${BUILDGO_SCRIPT}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/go
	COMMENT "Checking Trec Go runtime..."
	VERBATIM)
    elseif(arch MATCHES "mips64|mips64le")
      add_asm_sources(TREC_ASM_SOURCES rtl/trec_rtl_mips64.S)
    else()
      set(TREC_ASM_SOURCES)
    endif()
    add_compiler_rt_runtime(clang_rt.trec
      STATIC
      ARCHS ${arch}
      SOURCES ${TREC_SOURCES} ${TREC_ASM_SOURCES}
              $<TARGET_OBJECTS:RTInterception.${arch}>
              $<TARGET_OBJECTS:RTSanitizerCommon.${arch}>
              $<TARGET_OBJECTS:RTSanitizerCommonLibc.${arch}>
              $<TARGET_OBJECTS:RTSanitizerCommonCoverage.${arch}>
              $<TARGET_OBJECTS:RTSanitizerCommonSymbolizer.${arch}>
              $<TARGET_OBJECTS:RTUbsan.${arch}>
      ADDITIONAL_HEADERS ${TREC_HEADERS}
      CFLAGS ${TREC_RTL_CFLAGS}
      PARENT_TARGET trec)
    add_compiler_rt_runtime(clang_rt.trec_cxx
      STATIC
      ARCHS ${arch}
      SOURCES ${TREC_CXX_SOURCES}
              $<TARGET_OBJECTS:RTUbsan_cxx.${arch}>
      ADDITIONAL_HEADERS ${TREC_HEADERS}
      CFLAGS ${TREC_RTL_CFLAGS}
      PARENT_TARGET trec)
    list(APPEND TREC_RUNTIME_LIBRARIES clang_rt.trec-${arch}
                                       clang_rt.trec_cxx-${arch})
    add_sanitizer_rt_symbols(clang_rt.trec
      ARCHS ${arch}
      EXTRA rtl/trec.syms.extra)
    add_sanitizer_rt_symbols(clang_rt.trec_cxx
      ARCHS ${arch}
      EXTRA rtl/trec.syms.extra)
    add_dependencies(trec clang_rt.trec-${arch}
                          clang_rt.trec_cxx-${arch}
                          clang_rt.trec-${arch}-symbols
                          clang_rt.trec_cxx-${arch}-symbols)
  endforeach()
endif()

# Build libcxx instrumented with Trec.
if(COMPILER_RT_LIBCXX_PATH AND
   COMPILER_RT_LIBCXXABI_PATH AND
   COMPILER_RT_TEST_COMPILER_ID STREQUAL "Clang" AND
   NOT ANDROID)
  set(libcxx_trec_deps)
  foreach(arch ${TREC_SUPPORTED_ARCH})
    get_target_flags_for_arch(${arch} TARGET_CFLAGS)
    set(LIBCXX_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libcxx_trec_${arch})
    add_custom_libcxx(libcxx_trec_${arch} ${LIBCXX_PREFIX}
      DEPS ${TREC_RUNTIME_LIBRARIES}
      CFLAGS ${TARGET_CFLAGS} -fsanitize=trace
      USE_TOOLCHAIN)
    list(APPEND libcxx_trec_deps libcxx_trec_${arch}-build)
  endforeach()

  add_custom_target(libcxx_trec DEPENDS ${libcxx_trec_deps})
  set_target_properties(libcxx_trec PROPERTIES FOLDER "Compiler-RT Misc")
endif()

# if(COMPILER_RT_INCLUDE_TESTS)
#   add_subdirectory(tests)
# endif()
