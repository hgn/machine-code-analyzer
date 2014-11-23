#!/usr/bin/env python3

import os
import sys
import readline
import subprocess
import multiprocessing
import datetime

KERNEL_VERSION = "v3.17"

KERNELDIR        = "%s/%s" % (os.getcwd(), "linux-src")
KERNEL_SRC_DIR   = "%s/%s" % (KERNELDIR,   "src")
KERNEL_BUILD_DIR = "%s/%s" % (KERNELDIR,   "build")

NO_CPU = multiprocessing.cpu_count() - 1


print("Build kernel in %s" % (KERNELDIR))
if not os.path.exists(KERNELDIR):
    os.makedirs(KERNELDIR)
if not os.path.exists(KERNEL_SRC_DIR):
    os.makedirs(KERNEL_SRC_DIR)
if not os.path.exists(KERNEL_BUILD_DIR):
    os.makedirs(KERNEL_BUILD_DIR)
if not os.path.exists(KERNEL_SRC_DIR + "/.git"):
    print("No kernel found")
    print("Path to git kernel source? (I will clone the repository)")
    print("E.g.:")
    print("\tgit://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git")
    print("\tfile:///usr/src/linux")
    print("\tfile:///home/pfeifer/src/code/01-own/linux-dev/linux")
    line = sys.stdin.readline().rstrip()
    cmd = "git clone %s %s" % (line, KERNEL_SRC_DIR)
    print("Exectute: \"%s\"" % (cmd))
    os.system(cmd)
    cmd = "git --work-tree=%s checkout %s" % (KERNEL_SRC_DIR, KERNEL_VERSION)
    print("Exectute: \"%s\"" % (cmd))
    os.system(cmd)

os.chdir(KERNEL_SRC_DIR)

cmd = "make O=%s allyesconfig" % (KERNEL_BUILD_DIR)
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



