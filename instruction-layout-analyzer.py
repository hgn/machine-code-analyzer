#!/usr/bin/env python3


import sys
import argparse
import logging
import subprocess
import re

class BinaryBlob:

    def __init__(self):
        pass


class JumpAnalyser:

    def __init__(self):
        pass

    def pass1(self, blob):
        pass

    def pass2(self, blob):
        pass


    def final(self):
        pass


class InstructionLayoutAnalyzer:

    def __init__(self, filename):
        self.filename = filename
        self.log = logging.info

    def divide_parts(self, line):
        # 404e52:   e8 31 c2 ff ff          callq  401088 <_init>
        ret = dict()
        match = re.search(r'([\da-f]+):\s+((?:[0-9a-f]{2} )+)\s+(.*)', line)
        if not match:
            return None

        addr   = match.group(1).strip()
        opcode = match.group(2).strip()
        instr  = match.group(3).strip()

        # now unfold asm, following online tools
        # can be used to test regular expressions:
        # http://www.regexr.com/ or http://rubular.com/
        # movsd  0x1e4e(%rip),%xmm1        # 406c28 <symtab.5300+0x48>
        m1 = re.search(r'(\w+)\s+(\S+),(\S+)\s+#(.+)', instr)
        # mov    0x18(%rsp),%r12
        m2 = re.search(r'(\w+)\s+(\S+),(\S+)', instr)
        # jne    404e60 <__libc_csu_init+0x50>
        m3 = re.search(r'(\w+)\s+(\S+)\s+(<\S+>)', instr)
        # jmp    404b20 
        m4 = re.search(r'(\w+)\s+(\S+)', instr)
        # jmp
        m5 = re.search(r'(\w+)', instr)

        print("%s%s: %s%s\t\t%s%s%s" % (Colors.WARNING, addr, Colors.OKGREEN, opcode, Colors.FAIL, instr, Colors.ENDC))

        if m1:
            self.log("1 - movsd  0x1e4e(%rip),%xmm1        # 406c28 <symtab.5300+0x48>\n")
        elif m2:
            self.log("2 - mov    0x18(%rsp),%r12\n")
        elif m3:
            self.log("3 - jne    404e60 <__libc_csu_init+0x50>\n")
        elif m4:
            self.log("4 jmp 404b20\n")
        elif m5:
            self.log("5 jmp\n")
        else:
            self.log("Something wrong here; %s" % (line))
            sys.exit(1)

        mnemonic = match.group(1).strip()

        
        

    def parse_line(self, line):
        #sys.stdout.write("%s\n" % (line))
        self.divide_parts(line)


    def open_parse(self, filename):
        cmd = 'objdump -S %s' % (filename)
        self.log('execute: \"%s\"' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            self.parse_line(line.decode("utf-8").strip())


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
