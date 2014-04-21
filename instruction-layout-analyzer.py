#!/usr/bin/env python3


import sys
import argparse
import logging
import subprocess
import re

class InstructionCategory:

    UNKNOWN = 0

    @staticmethod
    def guess(instructon):
        return InstructionCategory.UNKNOWN


class BinaryAtom:

    TYPE_1 = 1
    TYPE_2 = 2
    TYPE_3 = 3
    TYPE_4 = 4
    TYPE_5 = 5
    TYPE_6 = 6

    def __init__(self, b_type, line, addr, opcode, kwargs):
        self.line       = line
        self.addr       = addr
        self.opcode_str = opcode
        self.opcode_len = len(opcode.replace(" ", "")) / 2
        self.atom_type  = b_type
        self.category   = InstructionCategory.UNKNOWN

        self.src = self.dst = self.jmp_addr = self.jmp_sym = None
        self.mnemonic = kwargs['mnemonic']

        if b_type == BinaryAtom.TYPE_1:
            self.src = kwargs['src']
            self.dst = kwargs['dst']
            self.jmp_addr = kwargs['jmp-addr']
            self.jmp_sym  = kwargs['jmp-sym']
        elif b_type == BinaryAtom.TYPE_2:
            self.src = kwargs['src']
            self.dst = kwargs['dst']
        elif b_type == BinaryAtom.TYPE_3:
            self.src = kwargs['src']
            self.jmp_addr = kwargs['jmp-addr']
            self.jmp_sym  = kwargs['jmp-sym']
        elif b_type == BinaryAtom.TYPE_4:
            self.src = kwargs['src']
            self.jmp_addr = kwargs['jmp-addr']
        elif b_type == BinaryAtom.TYPE_5:
            self.src = kwargs['src']
        elif b_type == BinaryAtom.TYPE_6:
            pass
        else:
            raise Exception("unknown code")

    def print(self):
        msg("%s\n" % (self.line)) 
        msg("MNEMONIC: %s  SRC:%s  DST:%s [OPCODE: %s,  LEN:%d]\n" %
            (self.mnemonic, self.src, self.dst,  self.opcode_str, self.opcode_len)) 
        


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
        m1 = re.search(r'(\w+)\s+(\S+),(\S+)\s+#\s+([\da-f]+)\s+<(.+)>', instr)
        # mov    0x18(%rsp),%r12
        m2 = re.search(r'(\w+)\s+(\S+),(\S+)', instr)
        # jmpq   *0x207132(%rip)        # 608218 <_GLOBAL_OFFSET_TABLE_+0x28>
        m3 = re.search(r'(\w+)\s+(\S+)\s+#\s+([\da-f]+)\s+<(.+)>', instr)
        # jne    404e60 <__libc_csu_init+0x50>
        m4 = re.search(r'(\w+)\s+(\S+)\s+<(\S+)>', instr)
        # jmp    404b20 
        m5 = re.search(r'(\w+)\s+(\S+)', instr)
        # jmp
        m6 = re.search(r'(\w+)', instr)

        log("%s%s: %s%s\t\t%s%s%s\n" %
            (Colors.WARNING, addr, Colors.OKGREEN, opcode, Colors.FAIL, instr, Colors.ENDC))
        d = dict()

        if m1:
            d['mnemonic'] = m1.group(1).strip()
            d['src'] = m1.group(2).strip()
            d['dst'] = m1.group(3).strip()
            d['jmp-addr'] = m1.group(4).strip()
            d['jmp-sym']  = m1.group(5).strip()
            dbg("1 movsd  0x1e4e(%rip),%xmm1        # 406c28 <symtab.5300+0x48>\n")
            return BinaryAtom(BinaryAtom.TYPE_1, line, addr, opcode, d)
        elif m2:
            d['mnemonic'] = m2.group(1).strip()
            d['src'] = m2.group(2).strip()
            d['dst'] = m2.group(3).strip()
            dbg("2 mov    0x18(%rsp),%r12\n")
            return BinaryAtom(BinaryAtom.TYPE_2, line, addr, opcode, d)
        elif m3:
            d['mnemonic'] = m3.group(1).strip()
            d['src'] = m3.group(2).strip()
            d['jmp-addr'] = m3.group(3).strip()
            d['jmp-sym']  = m3.group(4).strip()
            dbg("3 jmpq   *0x207132(%rip)        # 608218 <_GLOBAL_OFFSET_TABLE_+0x28>\n")
            return BinaryAtom(BinaryAtom.TYPE_3, line, addr, opcode, d)
        elif m4:
            d['mnemonic'] = m4.group(1).strip()
            d['src'] = m4.group(2).strip()
            d['jmp-addr'] = m4.group(3).strip()
            dbg("4 jne    404e60 <__libc_csu_init+0x50>\n")
            return BinaryAtom(BinaryAtom.TYPE_4, line, addr, opcode, d)
        elif m5:
            d['mnemonic'] = m5.group(1).strip()
            d['src'] = m5.group(2).strip()
            dbg("5 jmp    404b20\n")
            return BinaryAtom(BinaryAtom.TYPE_5, line, addr, opcode, d)
        elif m6:
            d['mnemonic'] = m6.group(1).strip()
            dbg("6 ret\n")
            return BinaryAtom(BinaryAtom.TYPE_6, line, addr, opcode, d)
        else:
            log("Something wrong here; %s" % (line))
            sys.exit(1)

        return None


    def parse_line(self, line):
        dbg("%s\n" % (line))
        return self.divide_parts(line)


    def open_parse(self, filename):
        cmd = 'objdump -S %s' % (filename)

        log('pass one: \"%s\"' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            atom = self.parse_line(line.decode("utf-8").strip())
            if atom is None:
                continue
            atom.print()

        return

        log('pass two: \"%s\"' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            atom = self.parse_line(line.decode("utf-8").strip())


    def run(self):
        msg("Instruction Layout Analyzer - 2014\n")
        msg("URL: https://github.com/hgn/instruction-layout-analyzer\n")
        msg("Filename to analyze: %s\n" % args.argument)
        self.open_parse(args.argument)


class Colors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'


def main(args):
    ila = InstructionLayoutAnalyzer(args.argument)
    ila.run()


log_enabled = False
dbg_enabled = False

def log(string):
    if not log_enabled:
        return
    sys.stderr.write("%s" % (string))

def dbg(string):
    if not dbg_enabled:
        return
    sys.stderr.write("%s" % (string))

def msg(string):
    sys.stdout.write("%s" % (string))

 
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
    parser.add_argument("-d", "--debug",
            help="debug",
            action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log_enabled = True
    if args.debug:
        log_debug = True

    if not sys.stdout.isatty():
        # reset colors
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
  
  # Setup logging
    main(args)
