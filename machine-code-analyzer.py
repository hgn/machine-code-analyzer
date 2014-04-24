#!/usr/bin/env python3


import sys
import os
import argparse
import logging
import subprocess
import re

class InstructionCategory:

    # other possible schema:
    #   Data Movement Instructions
    #        mov, push, pop, lea
    #   Arithmetic and Logic Instructions
    #        shl, not, neg, and, or, xor, idiv
    #   Control Flow Instructions
    #        call, ret, cmp, jcondition, jmp
    UNKNOWN = 0
    BRANCH_JUMP = 1
    LOAD = 2
    STORE = 3
    MOVE = 4
    FLOATING_POINT = 5
    EXCEPTION_TRAP = 6
    COMPARISON = 7
    ARITHMETIC_LOGICAL = 8
    SIMD = 9

    # http://en.wikipedia.org/wiki/Instruction_set
    DB = [
            ["callq", BRANCH_JUMP, "Saves procedure linking information on the stack and branches to function" ],
            ["retq", BRANCH_JUMP, "" ],
            ["mov",   MOVE, "Copying of data from one location to another" ],
            ["movl",   MOVE, "Copying of data from one location to another" ],
            ["test",   COMPARISON, "Perform  bitwise AND on two operands" ],
            ["sub",   ARITHMETIC_LOGICAL, "" ],
            ["je",   BRANCH_JUMP, "" ],
            ["jne",   BRANCH_JUMP, "" ],
            ["cvttss2si",   FLOATING_POINT, "Convert Scalar Single-Precision Floating-Point Value to Doubleword Integer with Truncation" ],
            ["push",  STORE, "Push data onto stack" ],
            ["jmp",   BRANCH_JUMP, "Transfers program control to a different point in the instruction not save return information" ],
            ["lea",    MOVE, "Memory addressing calculations" ], # can be seen as ARITHMETIC operation too
            ["jmpq",   BRANCH_JUMP, "Transfers program control to a different point in the instruction not save return information" ],
            ["invlpg", EXCEPTION_TRAP, "Invalidate TLB Entry for page at address" ],
    ]


    @staticmethod
    def guess(instructon):
        for i in InstructionCategory.DB:
            if instructon == i[0]:
                return i[1]
        return InstructionCategory.UNKNOWN

    @staticmethod
    def str(cat):
        if cat == InstructionCategory.UNKNOWN: return "unknown"
        if cat == InstructionCategory.BRANCH_JUMP: return "BRANCH_JUMP"
        if cat == InstructionCategory.LOAD: return "LOAD"
        if cat == InstructionCategory.STORE: return "STORE"
        if cat == InstructionCategory.MOVE: return "MOVE"
        if cat == InstructionCategory.FLOATING_POINT: return "FLOATING_POINT"
        if cat == InstructionCategory.EXCEPTION_TRAP: return "EXCEPTION_TRAP"
        if cat == InstructionCategory.COMPARISON: return "COMPARISON"
        if cat == InstructionCategory.ARITHMETIC_LOGICAL: return "ARITHMETIC_LOGICAL"
        if cat == InstructionCategory.SIMD: return "SIMD"
        raise Exception("Programmed error - no string repr defined")


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
        self.len_longest_filename = 10
        self.len_longest_size = 4

    def pass1(self, context, atom):
        self.len_longest_filename = max(len(context.function_name), self.len_longest_filename)
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
        self.len_longest_size = max(len(str(self.db[context.function_name]['size'])), self.len_longest_size)
        

    def pass2(self, context, atom):
        pass

    def show(self, json=False):
        if json:
            self.show_json()
        else:
            self.show_human()

    def show_human(self):
        msg("Functions Size:\n\n")
        fmt = "%%%d.%ds: %%%dd byte  [start: 0x%%x, end: 0x%%x]\n" % \
                (self.len_longest_filename, self.len_longest_filename, self.len_longest_size)
        for key in sorted(self.db.items(), key=lambda item: item[1]['size'], reverse=True):
            msg(fmt
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


class InstructionAnalyser:

    def __init__(self):
        self.instructions = dict()
        self.sum_opcode_length = 0
        self.max_opcode_length = 0

    def add_existing(self, atom):
        self.instructions[atom.mnemonic]['count'] += 1
        # now account instruction length variability
        if atom.opcode_len in self.instructions[atom.mnemonic]['instruction-lengths']:
            self.instructions[atom.mnemonic]['instruction-lengths'][atom.opcode_len] += 1
        else:
            self.instructions[atom.mnemonic]['instruction-lengths'][atom.opcode_len] = 1

    def add_new(self, atom):
        self.instructions[atom.mnemonic] = dict()
        self.instructions[atom.mnemonic]['count'] = 1
        self.instructions[atom.mnemonic]['category'] = InstructionCategory.guess(atom.mnemonic)
        # ok, this is more complicated but it is suitable for large
        # projects with millions of instructions
        self.instructions[atom.mnemonic]['instruction-lengths'] = dict()
        self.instructions[atom.mnemonic]['instruction-lengths'][atom.opcode_len] = 1
        self.instructions[atom.mnemonic]['line'] = atom.line

    def pass1(self, context, atom):
        self.max_opcode_length = max(self.max_opcode_length, atom.opcode_len)
        self.sum_opcode_length += atom.opcode_len
        if atom.mnemonic in self.instructions:
            self.add_existing(atom)
        else:
            self.add_new(atom)


    def pass2(self, context, atom):
        pass

    def show(self, json=False):
        if json:
            self.show_json()
        else:
            self.show_human()

    def show_human(self):
        msg("Program Instructions Analyses:\n\n")

        msg("General Information:\n")
        msg("    Instructions: %d\n" % (len(self.instructions.keys())))
        msg("    Overall Opcode length: %d byte\n" % (self.sum_opcode_length))
        msg("    Maximal Opcode length: %d byte\n" % (self.max_opcode_length))
        msg("\n")

        msg("Detailed Analysis:\n")

        msg("  Instruction  |  Count   |    Category  |    Length (avg, min, max)\n")
        msg("--------------------------------------------------------------------\n")
        for k in sorted(self.instructions.items(), key=lambda item: item[1]['count'], reverse=True):
            minval = min(k[1]['instruction-lengths'].keys())
            maxval = max(k[1]['instruction-lengths'].keys())
            sumval = 0.0
            for key, value in k[1]['instruction-lengths'].items():
                sumval += float(key) * float(value)
            sumval /= float(k[1]['count'])
            msg("%15.15s %10d %13.13s      %5.1f,%3.d,%3.d\n" %
                (k[0], k[1]['count'], InstructionCategory.str(k[1]['category']), sumval, minval, maxval))

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
        self.module['FunctionAnatomyAnalyzer']    = FunctionAnatomyAnalyzer()
        self.module['InstructionAnalyzer']        = InstructionAnalyser()


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

        dbg("%s%s: %s%s\t\t%s%s%s\n" %
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
            err("Something wrong here; %s" % (line))
            sys.exit(1)

        return None


    def process(self, filename):
        # maximal instruction length is 15 byte, per
        # "Intel® 64 and IA-32 Architectures Software Developer’s Manual"
        cmd = 'objdump -S --insn-width=16 %s' % (filename)
        context = Context()

        verbose('pass one: \"%s\"\n' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            atom = self.parse_line(line.decode("utf-8").strip(), context)
            if atom is None:
                continue
            if self.args.instruction_analyzer:
                self.module['InstructionAnalyzer'].pass1(context, atom)
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
        if self.args.instruction_analyzer:
            self.module['InstructionAnalyzer'].show(json=args.json)



    def run(self):
        msg("Instruction and Opcode Analyzer - (C) 2014\n\n")
        verbose("URL: https://github.com/hgn/instruction-layout-analyzer\n")
        verbose("Binary to analyze: %s\n" % args.argument)
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

def verbose(string):
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
    parser.add_argument("--instruction-analyzer",
            help="overview about used instructions",
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
