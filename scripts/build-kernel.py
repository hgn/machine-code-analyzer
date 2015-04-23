#!/usr/bin/env python3

import math
import os
import sys
import readline
import subprocess
import multiprocessing
import datetime
import tempfile
import shutil
import re

KERNEL_VERSION = "v4.0"

KERNELDIR        = "%s/%s" % (os.getcwd(), "linux-src")
KERNEL_SRC_DIR   = "%s/%s" % (KERNELDIR,   "src")
KERNEL_BUILD_DIR = "%s/%s" % (KERNELDIR,   "build")

NO_CPU = multiprocessing.cpu_count() - 1


def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def disable_config(config_file_path):
    options = [
            "CONFIG_FTRACE",
            "CONFIG_TRACING_SUPPORT",
            "HAVE_FTRACE_MCOUNT_RECORD",
            "CONFIG_GCOV_KERNEL",
            "CONFIG_ARCH_HAS_GCOV_PROFILE_ALL",
            "CONFIG_GCOV_PROFILE_ALL",
            "CONFIG_GCOV_FORMAT_AUTODETECT",
            "CONFIG_TRACE_IRQFLAGS",
            "CONFIG_DEBUG_KOBJECT",
            "CONFIG_DEBUG_BUGVERBOSE",
            "CONFIG_DEBUG_LIST",
            "CONFIG_DEBUG_PI_LIST",
            "CONFIG_DEBUG_SG",
            "CONFIG_DEBUG_NOTIFIERS",
            "CONFIG_DEBUG_CREDENTIALS",
            "CONFIG_RCU_TRACE",
            "CONFIG_RCU_TORTURE_TEST",
            "CONFIG_HAVE_FUNCTION_TRACER",
            "CONFIG_HAVE_FUNCTION_GRAPH_TRACER",
            "CONFIG_HAVE_DYNAMIC_FTRACE",
            "CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS",
            "CONFIG_HAVE_FTRACE_MCOUNT_RECORD",
            "CONFIG_HAVE_SYSCALL_TRACEPOINTS",
            "CONFIG_HAVE_FENTRY",
            "CONFIG_HAVE_C_RECORDMCOUNT",
            "CONFIG_TRACE_CLOCK",
            "CONFIG_STACKTRACE_SUPPORT",
            "CONFIG_FUNCTION_TRACER",
            "CONFIG_TRACING",
            "CONFIG_NOP_TRACER",
            "CONFIG_USER_STACKTRACE_SUPPORT",
            "CONFIG_PROVE_RCU_REPEATEDLY",
            "CONFIG_TORTURE_TEST",
            "CONFIG_DEBUG_ATOMIC_SLEEP",
            "CONFIG_EVENT_TRACING",
            "CONFIG_CONTEXT_SWITCH_TRACER",
            "CONFIG_TRACER_MAX_TRACE",
            "CONFIG_FUNCTION_GRAPH_TRACER",
            "CONFIG_IRQSOFF_TRACER",
            "CONFIG_SCHED_TRACER",
            "CONFIG_FTRACE_SYSCALLS",
            "CONFIG_STACK_TRACER",
            "CONFIG_TRACER_SNAPSHOT",
            "CONFIG_TRACER_SNAPSHOT_PER_CPU_SWAP",
            "CONFIG_BRANCH_PROFILE_NONE",
            "CONFIG_BLK_DEV_IO_TRACE",
            "CONFIG_KPROBE_EVENT",
            "CONFIG_UPROBE_EVENT",
            "CONFIG_BPF_EVENTS",
            "CONFIG_PROBE_EVENTS",
            "CONFIG_DYNAMIC_FTRACE",
            "CONFIG_DYNAMIC_FTRACE_WITH_REGS",
            "CONFIG_FUNCTION_PROFILER",
            "CONFIG_FTRACE_MCOUNT_RECORD",
            "CONFIG_FTRACE_STARTUP_TEST",
            "CONFIG_FTRACE_SELFTEST",
            "CONFIG_EVENT_TRACE_TEST_SYSCALLS",
            "CONFIG_MMIOTRACE",
            "CONFIG_MMIOTRACE_TEST",
            "CONFIG_TRACEPOINT_BENCHMARK",
            "CONFIG_RING_BUFFER_BENCHMARK",
            "CONFIG_RING_BUFFER_STARTUP_TEST",
            "CONFIG_TRACE_ENUM_MAP_FILE",
            "CONFIG_KGDB",
            "CONFIG_KASAN",
            "CONFIG_PROVE_RCU",
            "CONFIG_LOCKDEP_SUPPORT",
            "CONFIG_LOCKDEP",
            "CONFIG_DEBUG_LOCKDEP",
            "CONFIG_STACKTRACE",
            "CONFIG_DEBUG_KOBJECT_RELEASE",
            "CONFIG_DEBUG_WW_MUTEX_SLOWPATH",
            "CONFIG_DEBUG_RT_MUTEXES",
            "CONFIG_DEBUG_SPINLOCK",
            "CONFIG_DEBUG_MUTEXES",
            "CONFIG_LOCK_STAT",
            "CONFIG_PROVE_LOCKING",
            "CONFIG_DEBUG_LOCK_ALLOC",
            "CONFIG_CC_OPTIMIZE_FOR_SIZE"
            ]
    #Create temp file
    fh, abs_path = tempfile.mkstemp()
    new_file = open(abs_path,'w')
    old_file = open(config_file_path)
    for line in old_file:
        found = False
        for option in options:
            if re.match("%s=" % (option), line):
                print("Disabling kernel config %s" % (option))
                new_file.write("# %s is not set\n" % (option))
                found = True
        if not found:
            new_file.write(line)
    #close temp file
    new_file.close()
    os.close(fh)
    old_file.close()
    #Remove original file
    os.remove(config_file_path)
    #Move new file
    shutil.move(abs_path, config_file_path)
    print("New config file path: %s\n" % (config_file_path))


filename = "%s/vmlinux" % (KERNEL_BUILD_DIR)
if os.path.isfile(filename):
    print("Kernel already build, nothing to do (%s)" % (filename))
    print("(remove or rename file to re-build kernel)")
    sys.exit(1)

    

print("Build kernel in %s" % (KERNELDIR))
if not os.path.exists(KERNELDIR):
    os.makedirs(KERNELDIR)
if not os.path.exists(KERNEL_SRC_DIR):
    os.makedirs(KERNEL_SRC_DIR)
if not os.path.exists(KERNEL_BUILD_DIR):
    os.makedirs(KERNEL_BUILD_DIR)
if not os.path.exists(KERNEL_SRC_DIR + "/.git"):
    print("No kernel found")
    print("Path to git kernel source? (I will clone the repository!)")
    print("E.g.:")
    print("\tgit://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git")
    print("\tfile:///usr/src/linux")
    print("\tfile:///home/pfeifer/src/code/01-own/linux-dev/linux")
    line = sys.stdin.readline().rstrip()
    cmd = "git clone %s %s" % (line, KERNEL_SRC_DIR)
    print("Exectute: \"%s\"" % (cmd))
    os.system(cmd)

original_dir = os.getcwd()
os.chdir(KERNEL_SRC_DIR)

cmd = "git checkout %s" % (KERNEL_VERSION)
print("Exectute: \"%s\"" % (cmd))
os.system(cmd)

cmd = "make O=%s allyesconfig" % (KERNEL_BUILD_DIR)
print("Exectute: \"%s\"" % (cmd))
print("This may take several minutes to some hours, depending on your CPU")
os.system(cmd)

disable_config("%s/.config" % (KERNEL_BUILD_DIR))

cmd = "make O=%s oldconfig" % (KERNEL_BUILD_DIR)
print("Exectute: \"%s\"" % (cmd))
os.system(cmd)

build_start = datetime.datetime.now()
# EXTRA_CFLAGS=\"-g -fverbose-asm\"
cmd = "nice make V=1 -j %d O=%s" % (NO_CPU, KERNEL_BUILD_DIR)
print("Exectute: \"%s\"" % (cmd))
os.system(cmd)
diff = datetime.datetime.now() - build_start
diff_min = diff.total_seconds() / 60.0
print("Build duration: %.1d minutes" % (diff_min))

os.chdir(original_dir)

filename = "%s/vmlinux" % (KERNEL_BUILD_DIR)
if os.path.isfile(filename):
    cmd = "cp %s ." % (filename)
    print("Exectute: \"%s\"" % (cmd))
    os.system(cmd)
else:
    print("Cannot compile kernel!\n")

print("vmlinux size: %s" % ( sizeof_fmt(os.stat("vmlinux").st_size)))
