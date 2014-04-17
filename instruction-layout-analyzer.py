#!/usr/bin/env python3


import sys
import argparse
import logging
import subprocess
import re


class InstructionLayoutAnalyzer:

    def __init__(self, filename):
        self.filename = filename
        self.log = logging.info

    def divide_parts(self, line):
        # 404e52:   e8 31 c2 ff ff          callq  401088 <_init>
        ret = dict()
        opcode = ""
        match = re.search(r' ([\da-f]+):\s+((?:[0-9a-f]{2} )+)', line)
        if match:
            opcode += match.group(2).strip() + " "
            print("%s%s%s" % (Colors.WARNING, opcode, Colors.ENDC))
        

    def parse_line(self, line):
        sys.stdout.write("%s\n" % (line))
        self.divide_parts(line)


    def open_parse(self, filename):
        cmd = 'objdump -S %s' % (filename)
        self.log('execute: \"%s\"' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            self.parse_line(line.decode("utf-8").rstrip())


    def run(self):
        self.log("Filename to analyze: %s" % args.argument)
        self.open_parse(args.argument)


class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'


def main(args, loglevel):
    logging.basicConfig(format="%(levelname)s: %(message)s", level=loglevel)

    ila = InstructionLayoutAnalyzer(args.argument)
    ila.run()

 
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
            description = "Does a thing to some stuff.",
            fromfile_prefix_chars = '@')

    parser.add_argument("argument",
            help = "filename tp parse",
            metavar = "filename")
    parser.add_argument("-v", "--verbose",
            help="increase output verbosity",
            action="store_true")
    args = parser.parse_args()
  
  # Setup logging
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO
        
        
    main(args, loglevel)
