#!/usr/bin/env python3


import sys
import argparse
import logging
import subprocess
import re

class InstructionCategory:

    UNKNOWN = 0
    BRANCH_JUMP = 1
    LOAD = 2
    STORE = 3
    MOVE = 4
    FLOATING_POINT = 5
    EXCEPTION_TRAP = 6
    COMPARISON = 7
    ARITHMETIC_LOGICAL = 8


    @staticmethod
    def guess(instructon):
        return InstructionCategory.UNKNOWN

class Context:

    def __init__(self):
        self.function_name = None
        self.function_start_address  = None
        self.section_name  = None


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
        dbg("%s\n" % (self.line))
        dbg("MNEMONIC: %s  SRC:%s  DST:%s [OPCODE: %s,  LEN:%d]\n" %
            (self.mnemonic, self.src, self.dst,  self.opcode_str, self.opcode_len)) 


class FunctionAnatomyAnalyzer:

    def __init__(self):
        self.db = dict()

    def pass1(self, context, atom):
        if not context.function_name in self.db:
            self.db[context.function_name] = dict()
            self.db[context.function_name]['start'] = \
                    context.function_start_address
            self.db[context.function_name]['end'] = \
                    context.function_start_address + atom.opcode_len
            self.db[context.function_name]['size'] = \
                    self.db[context.function_name]['end'] - self.db[context.function_name]['start']
            return

        self.db[context.function_name]['end'] += atom.opcode_len
        self.db[context.function_name]['size'] = \
                self.db[context.function_name]['end'] - self.db[context.function_name]['start']
        

    def pass2(self, context, atom):
        pass

    def show(self, json=False):
        if json:
            self.show_json()
        else:
            self.show_human()

    def show_human(self):
        msg("Functions Anatomy:\n")
        for key in sorted(self.db.items(), key=lambda item: item[1]['size'], reverse=True):
            msg("%30.30s  [size: %6d byte, start:0x%x, end:0x%x]\n"
                % (key[0], key[1]['size'], key[1]['start'], key[1]['end']))

    def show_json(self):
        pass


class FunctionBranchJumpAnalyser:

    def __init__(self):
        pass

    def pass1(self, context, atom):
        pass

    def pass2(self, context, atom):
        pass

    def show(self, json=False):
        if json:
            self.show_json()
        else:
            self.show_human()

    def show_human(self):
        msg("Functions Branches and Jumps:\n")

    def show_json(self):
        pass


class InstructionLayoutAnalyzer:

    def __init__(self, args):
        self.args = args
        self.filename = args.argument
        self.init_modules()


    def init_modules(self):
        self.module = dict()
        self.module['FunctionBranchJumpAnalyser'] = FunctionBranchJumpAnalyser()
        self.module['FunctionAnatomyAnalyzer'] = FunctionAnatomyAnalyzer()


    def try_parse_update_context(self, line, context):
        if line == "":
            # empty line, do nothing
            return
        # ./ipproof-client:     file format
        match = re.search(r'\s*' + self.filename + ':\s+file format', line)
        if match:
            return

        # 0000000000401088 <_init>:
        match = re.search(r'^([\da-f]+)\s+<(\S+)>', line)
        if match:
            context.function_start_address = int(match.group(1).strip(), 16)
            context.function_name = match.group(2).strip()
            dbg("Function name: %s, function start address: 0x%x\n" %
                (context.function_name, context.function_start_address))
            return
        # Disassembly of section .plt:
        match = re.search(r'Disassembly of section\s+(\S+):', line)
        if match:
            context.section_name = match.group(1).strip()
            dbg("Section name: %s\n" % (context.section_name))
            return

        # unknown lines are probably annotated source code
        # lines from DWARF info - just skip it
        #log("Unknown line: \"%s\"\n" % (line))


    def is_wrapped_line_update(self, line):
        match = re.search(r'([\da-f]+):\s+((?:[0-9a-f]{2} )+)', line)
        if match:
            raise Exception("Line wrapped!")


    def parse_line(self, line, context):
        # 404e52:   e8 31 c2 ff ff          callq  401088 <_init>
        ret = dict()
        match = re.search(r'([\da-f]+):\s+((?:[0-9a-f]{2} )+)\s+(.*)', line)
        if not match:
            # Special case overlong wrapped in two lines:
            #  4046c7:       48 ba cf f7 53 e3 a5    movabs $0x20c49ba5e353f7cf,%rdx
            #  4046ce:       9b c4 20
            self.is_wrapped_line_update(line)
            # no instruction, but maybe function information to
            # update context data
            self.try_parse_update_context(line, context)
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


    def process(self, filename):
        cmd = 'objdump -S --insn-width=30 %s' % (filename)
        context = Context()

        log('pass one: \"%s\"\n' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            atom = self.parse_line(line.decode("utf-8").strip(), context)
            if atom is None:
                continue
            # Function Anatomy Analyzer is always processed, because
            # the analyzer serves as a ground work for other analyzes
            self.module['FunctionAnatomyAnalyzer'].pass1(context, atom)
            if self.args.function_branch_jump:
                self.module['FunctionBranchJumpAnalyser'].pass1(context, atom)
            atom.print()

        return

    def show(self):
        if self.args.function_anatomy:
            self.module['FunctionAnatomyAnalyzer'].show(json=args.json)
        if self.args.function_branch_jump:
            self.module['FunctionBranchJumpAnalyser'].show(json=args.json)



    def run(self):
        msg("Instruction and Opcode Analyzer - 2014\n")
        msg("URL: https://github.com/hgn/instruction-layout-analyzer\n")
        msg("Binary to analyze: %s\n" % args.argument)
        self.process(args.argument)
        self.show()


class Colors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'


def main(args):
    ila = InstructionLayoutAnalyzer(args)
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
    parser.add_argument("-j", "--json",
            help="print results JSON encoded",
            action="store_true")
    parser.add_argument("--function-branch-jump",
            help="function local branch and jump analyzer",
            action="store_true")
    parser.add_argument("--function-anatomy",
            help="function anatomy analyzer",
            action="store_true")
    parser.add_argument("-d", "--debug",
            help="debug",
            action="store_true")
    args = parser.parse_args()

    if args.verbose:
        log_enabled = True
    if args.debug:
        dbg_enabled = True

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
