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

KERNEL_VERSION = "v3.17"

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
            "CONFIG_HAVE_DYNAMIC_FTRACE",
            "HAVE_FTRACE_MCOUNT_RECORD"
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

original_dir = os.getcwd()
os.chdir(KERNEL_SRC_DIR)

cmd = "make O=%s allyesconfig" % (KERNEL_BUILD_DIR)
print("Exectute: \"%s\"" % (cmd))
os.system(cmd)

disable_config("%s/.config" % (KERNEL_BUILD_DIR))

cmd = "make O=%s oldconfig" % (KERNEL_BUILD_DIR)
print("Exectute: \"%s\"" % (cmd))
os.system(cmd)
sys.exit(0)


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
