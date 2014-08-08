#!/usr/bin/env python3
#
# Email: Hagen Paul Pfeifer <hagen@jauu.net>

# Machine-Code-Analyzer is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# MachineCodeAnalyzer is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MachineCodeAnalyzer. If not, see <http://www.gnu.org/licenses/>.


import sys
import os
import optparse
import subprocess
import pprint
import re


pp = pprint.PrettyPrinter(indent=4)

__programm__ = "machine-code-analyzer"
__author__   = "Hagen Paul Pfeifer"
__version__  = "1"
__license__  = "GPLv3"

# custom exceptions
class ArgumentException(Exception): pass
class InternalSequenceException(Exception): pass
class InternalException(Exception): pass
class SequenceContainerException(InternalException): pass
class NotImplementedException(InternalException): pass
class SkipProcessStepException(Exception): pass
class UnitException(Exception): pass


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
        self.caller.verbose("%s\n" % (self.line))
        self.caller.verbose("MNEMONIC: %s  SRC:%s  DST:%s [OPCODE: %s,  LEN:%d]\n" %
            (self.mnemonic, self.src, self.dst,  self.opcode_str, self.opcode_len)) 


class Common:

    def err(self, msg):
        sys.stderr.write(msg)

    def verbose(self, msg):
        if not self.opts.verbose:
            return
        sys.stderr.write(msg)

    def msg(self, msg):
        sys.stdout.write(msg)

    def debug(self, msg):
        pass


class Parser:

    def __init__(self, opts):
        self.args = opts
        self.filename = opts.filename

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
            self.caller.debug("Function name: %s, function start address: 0x%x\n" %
                (context.function_name, context.function_start_address))
            return
        # Disassembly of section .plt:
        match = re.search(r'Disassembly of section\s+(\S+):', line)
        if match:
            context.section_name = match.group(1).strip()
            self.caller.debug("Section name: %s\n" % (context.section_name))
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

        self.caller.debug("%s%s: %s%s\t\t%s%s%s\n" %
            (Colors.WARNING, addr, Colors.OKGREEN, opcode, Colors.FAIL, instr, Colors.ENDC))
        d = dict()

        if m1:
            d['mnemonic'] = m1.group(1).strip()
            d['src'] = m1.group(2).strip()
            d['dst'] = m1.group(3).strip()
            d['jmp-addr'] = m1.group(4).strip()
            d['jmp-sym']  = m1.group(5).strip()
            self.caller.debug("1 movsd  0x1e4e(%rip),%xmm1        # 406c28 <symtab.5300+0x48>\n")
            return BinaryAtom(BinaryAtom.TYPE_1, line, addr, opcode, d)
        elif m2:
            d['mnemonic'] = m2.group(1).strip()
            d['src'] = m2.group(2).strip()
            d['dst'] = m2.group(3).strip()
            self.caller.debug("2 mov    0x18(%rsp),%r12\n")
            return BinaryAtom(BinaryAtom.TYPE_2, line, addr, opcode, d)
        elif m3:
            d['mnemonic'] = m3.group(1).strip()
            d['src'] = m3.group(2).strip()
            d['jmp-addr'] = m3.group(3).strip()
            d['jmp-sym']  = m3.group(4).strip()
            self.caller.debug("3 jmpq   *0x207132(%rip)        # 608218 <_GLOBAL_OFFSET_TABLE_+0x28>\n")
            return BinaryAtom(BinaryAtom.TYPE_3, line, addr, opcode, d)
        elif m4:
            d['mnemonic'] = m4.group(1).strip()
            d['src'] = m4.group(2).strip()
            d['jmp-addr'] = m4.group(3).strip()
            self.caller.debug("4 jne    404e60 <__libc_csu_init+0x50>\n")
            return BinaryAtom(BinaryAtom.TYPE_4, line, addr, opcode, d)
        elif m5:
            d['mnemonic'] = m5.group(1).strip()
            d['src'] = m5.group(2).strip()
            self.caller.debug("5 jmp    404b20\n")
            return BinaryAtom(BinaryAtom.TYPE_5, line, addr, opcode, d)
        elif m6:
            d['mnemonic'] = m6.group(1).strip()
            self.caller.debug("6 ret\n")
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

        self.caller.verbose('pass one: \"%s\"\n' % (cmd))
        p = subprocess.Popen(cmd.split(), shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in p.stdout.readlines():
            atom = self.parse_line(line.decode("utf-8").strip(), context)
            if atom is None:
                continue
            self.caller.process(context, atom)

            #if self.args.instruction_analyzer:
            #    self.module['InstructionAnalyzer'].pass1(context, atom)
            # Function Anatomy Analyzer is always processed, because
            # the analyzer serves as a ground work for other analyzes
            #self.module['FunctionAnatomyAnalyzer'].pass1(context, atom)
            #if self.args.function_branch_jump:
            #    self.module['FunctionBranchJumpAnalyser'].pass1(context, atom)
            #atom.print()

        return


    def run(self, caller):
        self.caller = caller
        self.caller.msg("Instruction and Opcode Analyzer - (C) 2014\n\n")
        self.caller.verbose("URL: https://github.com/hgn/instruction-layout-analyzer\n")
        self.caller.verbose("Binary to analyze: %s\n" % self.args.filename)
        statinfo = os.stat(self.args.filename)
        if statinfo.st_size > 50000:
            self.caller.msg("File larger then 50kbyte, analysis may take some time")

        self.process(self.args.filename)


class FunctionAnatomyAnalyzer:

    def __init__(self):
        pass

    def run(self):
        pass


class InstructionAnalyzer(Common):

    def __init__(self):
        self.parse_local_options()
        self.instructions = dict()
        self.sum_opcode_length = 0
        self.max_opcode_length = 0

    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.usage = "InstructionAnalyzer"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                          action="store_true", help="show verbose")

        self.opts, args = parser.parse_args(sys.argv[0:])

        if len(args) != 3:
            self.err("No <binary> argument given, exiting\n")
            sys.exit(1)

        self.verbose("Analyze binary: %s\n" % (sys.argv[-1]))
        self.opts.filename = args[-1]

    def run(self):
        self.parser = Parser(self.opts)
        self.parser.run(self)
        self.show()

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

    def process(self, context, atom):
        self.max_opcode_length = max(self.max_opcode_length, atom.opcode_len)
        self.sum_opcode_length += atom.opcode_len
        if atom.mnemonic in self.instructions:
            self.add_existing(atom)
        else:
            self.add_new(atom)


    def show(self, json=False):
        if json:
            self.show_json()
        else:
            self.show_human()

    def show_human(self):
        self.msg("Program Instructions Analyses:\n\n")

        overall = 0
        for key, value in self.instructions.items():
            overall += value['count']

        self.msg("General Information:\n")
        self.msg("    No different Instructions: %d\n" % (len(self.instructions.keys())))
        self.msg("    No Instructions: %d\n" % (overall))
        self.msg("    Overall Opcode length: %d byte\n" % (self.sum_opcode_length))
        self.msg("    Maximal Opcode length: %d byte\n" % (self.max_opcode_length))
        self.msg("\n")

        self.msg("Detailed Analysis:\n")

        self.msg("  Instruction  |  Count    [    %]  |    Category  | Length (avg, min, max)\n")
        self.msg("--------------------------------------------------------------------\n")
        for k in sorted(self.instructions.items(), key=lambda item: item[1]['count'], reverse=True):
            minval = min(k[1]['instruction-lengths'].keys())
            maxval = max(k[1]['instruction-lengths'].keys())
            sumval = 0.0
            for key, value in k[1]['instruction-lengths'].items():
                sumval += float(key) * float(value)
            sumval /= float(k[1]['count'])
            percent = (float(k[1]['count']) / (overall)) * 100.0
            self.msg("%15.15s %10d [%5.2f]  %13.13s      %5.1f,%3.d,%3.d\n" %
                (k[0], k[1]['count'], percent, InstructionCategory.str(k[1]['category']), sumval, minval, maxval))

    def show_json(self):
        pass


class MachineCodeAnalyzer:

    modes = {
       "function-anatomy":     [ "FunctionAnatomyAnalyzer", "Function anatomy information" ],
       "instruction-analyzer": [ "InstructionAnalyzer",     "Information about instructions" ]
            }

    def __init__(self):
        if not sys.stdout.isatty():
            # reset colors
            Colors.HEADER = ''
            Colors.OKBLUE = ''
            Colors.OKGREEN = ''
            Colors.WARNING = ''
            Colors.FAIL = ''
            Colors.ENDC = ''


    def which(self, program):
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            full_path = os.path.join(path, program)
            if os.path.isfile(full_path) and os.access(full_path, os.X_OK):
                return full_path
        return None

    def print_version(self):
        sys.stdout.write("%s\n" % (__version__))

    def print_usage(self):
        sys.stderr.write("Usage: mca [-h | --help]" +
                         " [--version]" +
                         " <modulename> [<module-options>] <binary>\n")

    def print_welcome(self):
        major, minor, micro, releaselevel, serial = sys.version_info
        self.logger.critical("mca 2010-2013 Hagen Paul Pfeifer and others (c)")
        self.logger.critical("http://research.protocollabs.com/mca/")
        self.logger.info("python: %s.%s.%s [releaselevel: %s, serial: %s]" %
                (major, minor, micro, releaselevel, serial))


    def print_modules(self):
        for i in MachineCodeAnalyzer.modes.keys():
            sys.stderr.write("   %-15s - %s\n" % (i, MachineCodeAnalyzer.modes[i][1]))


    def args_contains(self, argv, *cmds):
        for cmd in cmds:
            for arg in argv:
                if arg == cmd: return True
        return False

    def check_binary_path(self, binary):
        statinfo = os.stat(binary)
        if not statinfo.st_size > 0:
            sys.stderr.write("File %s contains no content" % (binary))
            return False
        return True


    def parse_global_otions(self):
        if len(sys.argv) <= 2:
            self.print_usage()
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        self.binary_path = sys.argv[-1]
        if self.check_binary_path(self.binary_path) == False:
            sys.stderr.write("Failed to open binary\n")
            return None

        # --version can be placed somewhere in the
        # command line and will evalutated always: it is
        # a global option
        if self.args_contains(sys.argv, "--version"):
            self.print_version()
            return None

        # -h | --help as first argument is treated special
        # and has other meaning as a submodule
        if self.args_contains(sys.argv[1:2], "-h", "--help"):
            self.print_usage()
            sys.stderr.write("Available modules:\n")
            self.print_modules()
            return None

        submodule = sys.argv[1].lower()
        if submodule not in MachineCodeAnalyzer.modes:
            self.print_usage()
            sys.stderr.write("Module \"%s\" not known, available modules are:\n" %
                             (submodule))
            self.print_modules()
            return None

        classname = MachineCodeAnalyzer.modes[submodule][0]
        return classname


    def run(self):
        classtring = self.parse_global_otions()
        if not classtring:
            return 1

        classinstance = globals()[classtring]()
        classinstance.run()

        return 0

class Colors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'



if __name__ == "__main__":
    try:
        mca = MachineCodeAnalyzer()
        sys.exit(mca.run())
    except KeyboardInterrupt:
        sys.stderr.write("SIGINT received, exiting\n")
