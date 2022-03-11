//===-- trec_flags.inc ------------------------------------------*- C++
//-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// TRec runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef TREC_FLAG
#error "Define TREC_FLAG prior to including this file!"
#endif

// TREC_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

TREC_FLAG(bool, enable_annotations, true,
               "Enable dynamic annotations, otherwise they are no-ops.")
// Suppress a race report if we've already output another race report
// with the same stack.
TREC_FLAG(
    bool, suppress_equal_stacks, true,
    "Suppress a race report if we've already output another race report "
    "with the same stack.")
TREC_FLAG(
    bool, suppress_equal_addresses, true,
    "Suppress a race report if we've already output another race report "
    "on the same address.")

TREC_FLAG(bool, report_bugs, false,
               "Turns off bug reporting entirely (useful for benchmarking).")
TREC_FLAG(bool, report_thread_leaks, false, "Report thread leaks at exit?")
TREC_FLAG(bool, report_destroy_locked, false,
               "Report destruction of a locked mutex?")
TREC_FLAG(bool, report_mutex_bugs, false,
               "Report incorrect usages of mutexes and mutex annotations?")
TREC_FLAG(bool, report_signal_unsafe, false,
               "Report violations of async signal-safety "
               "(e.g. malloc() call from a signal handler).")
TREC_FLAG(bool, report_atomic_races,false,
               "Report races between atomic and plain memory accesses.")
TREC_FLAG(
    bool, force_seq_cst_atomics, false,
    "If set, all atomics are effectively sequentially consistent (seq_cst), "
    "regardless of what user actually specified.")
TREC_FLAG(bool, print_benign, false,
               "Print matched \"benign\" races at exit.")
TREC_FLAG(bool, halt_on_error, false, "Exit after first reported error.")
TREC_FLAG(int, atexit_sleep_ms, 1000,
               "Sleep in main thread before exiting for that many ms "
               "(useful to catch \"at exit\" races).")
TREC_FLAG(const char *, profile_memory, "",
               "If set, periodically write memory profile to that file.")
TREC_FLAG(int, flush_memory_ms, 0, "Flush shadow memory every X ms.")
TREC_FLAG(int, flush_symbolizer_ms, 5000,
               "Flush symbolizer caches every X ms.")
TREC_FLAG(int, memory_limit_mb, 0,
               "Resident memory limit in MB to aim at."
               "If the process consumes more memory, then TRec will flush "
               "shadow memory.")
TREC_FLAG(
    bool, stop_on_start, false,
    "Stops on start until __trec_resume() is called (for debugging).")
TREC_FLAG(bool, running_on_valgrind, false,
               "Controls whether RunningOnValgrind() returns true or false.")
// There are a lot of goroutines in Go, so we use smaller history.
TREC_FLAG(
    int, history_size, SANITIZER_GO ? 1 : 3,
    "Per-thread history size, controls how many previous memory accesses "
    "are remembered per thread.  Possible values are [0..7]. "
    "history_size=0 amounts to 32K memory accesses.  Each next value doubles "
    "the amount of memory accesses, up to history_size=7 that amounts to "
    "4M memory accesses.  The default value is 2 (128K memory accesses).")
TREC_FLAG(int, io_sync, 1,
               "Controls level of synchronization implied by IO operations. "
               "0 - no synchronization "
               "1 - reasonable level of synchronization (write->read)"
               "2 - global synchronization of all IO operations.")
TREC_FLAG(
    bool, die_after_fork, true,
    "Die after multi-threaded fork if the child creates new threads.")
TREC_FLAG(const char *, suppressions, "", "Suppressions file name.")
TREC_FLAG(bool, ignore_interceptors_accesses, SANITIZER_MAC ? true : false,
               "Ignore reads and writes from all interceptors.")
TREC_FLAG(
    bool, ignore_noninstrumented_modules, SANITIZER_MAC ? true : false,
    "Interceptors should only detect races when called from instrumented "
    "modules.")
TREC_FLAG(
    bool, shared_ptr_interceptor, true,
    "Track atomic reference counting in libc++ shared_ptr and weak_ptr.")
TREC_FLAG(bool, recorder_on, false, "Recorde event trace?")
TREC_FLAG(bool, output_trace, true, "Output trace.")
TREC_FLAG(bool, output_metadata, true, "Output metadata.")
TREC_FLAG(bool, no_stack, false, "Do not record memory operation on stack.")
TREC_FLAG(bool, record_branch, true, "Record conditional branch insts.")
TREC_FLAG(bool, record_func_enter_exit, true, "Record function enter/exit insts.")
TREC_FLAG(bool, record_func_param, true, "Record function parameter insts.")
