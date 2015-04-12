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
import ctypes

# Optional packages
# Arch Linux:
#   pacman -S extra/python-pip
# Debian based
#   aptitude install python3-pip  python3-lxml
# Finally:
#   pip3 install pygal
try:
    import pygal
except ImportError:
    pygal = None


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


class FunctionExcluder:

    def __init__(self):
        self.exclude_files = ['_start', '_fini', '__libc_csu_fini',
                              '__do_global_dtors_aux', '__libc_csu_init',
                              'register_tm_clones', 'frame_dummy',
                              '__init', 'deregister_tm_clones', '_init']

    def is_excluded(self, function_name):
        if function_name.endswith("@plt"):
            return True
        if function_name.endswith("@plt-0x10"):
            return True
        if function_name in self.exclude_files:
            return True
        return False


class RetObj:

    STATIC = 0
    DYNAMIC = 1
    NO_STACK = 2

    def __init__(self, stack_type):
        self.stack_type = stack_type
        self.register = None


class InstructionCategory:
    UNKNOWN = 0

    # E.g. http://flint.cs.yale.edu/cs422/doc/24547012.pdf
    BINARY_ARITHMETIC = 32
    DECIMAL_ARITHMETIC = 33
    LOGICAL = 34
    SHIFT_ROTATE = 35
    BIT_BYTE = 6
    CONTROL_TRANSFER = 37
    STRING = 38
    FLAG_CONTROL = 39
    SEGMENT_REGISTER = 40
    MISC = 41
    DATA_TRANSFER =  42
    FLOATING_POINT = 43
    SYSTEM = 44

    SIMD = 9
    MMX = 10
    SSE = 11
    E3DN = 12
    SSE2 = 13
    SSE3 = 14
    SSSE3 = 15
    SSE41 = 16
    SSE42 = 17
    SSE4A = 18
    AES = 19
    AVX = 20
    FMA = 21
    FMA4 = 22
    CPUID = 23
    MMXEXT = 24

    DBn = {
            """mov movl cmove xchg bswap xadd push pushq pop in out""" :
            [ DATA_TRANSFER , None ],
            """add addl sub adc imul mul div inc neg cmp cmpl cmpq""" :
            [ BINARY_ARITHMETIC , None ],
            """daa das aaa aas aam aad""" :
            [ DECIMAL_ARITHMETIC , None ],
            """and or not xor""" :
            [ LOGICAL , None ],
            """sar shr sal shl rol rcr rcl shrd shld""" :
            [ SHIFT_ROTATE , None ],
            """test bt bts btr btc sete""" :
            [ BIT_BYTE , None ],
            """jmp je jbe jg jz ja jc jle js loop call callq retq jne jmpq
            enter leave leaveq ret iret""" :
            [ CONTROL_TRANSFER , None ],
            """movs movsb rep""" :
            [ STRING , None ],
            """stc clc sti cli pushf popf""" :
            [ FLAG_CONTROL , None ],
            """lds les lgs""" :
            [ SEGMENT_REGISTER , None ],
            """lea nop nopl ud2 xlat""" :
            [ MISC, None ],
            """cvttss2si""" :
            [ FLOATING_POINT, None ],
            """invlpg lgdt lldt ltr str arpl lock hlt rsm sysenter sysleave
            rdtsc""" :
            [ SYSTEM, None ],
            """emms movd movq packssdw packsswb packuswb paddb paddd paddsb
            paddsw paddusb paddusw paddw pand pandn pcmpeqb pcmpeqd pcmpeqw
            pcmpgtb pcmpgtd pcmpgtw pmaddwd pmulhw pmullw por pslld psllq psllw
            psrad psraw psrld psrlq psrlw psubb psubd psubsb psubsw psubusb
            psubusw psubw punpckhbw punpckhdq punpckhwd punpcklbw punpckldq
            punpcklwd pxor""" :
            [ MMX, None ],
            """addps addss andnps andps cmpeqps cmpeqss cmpleps cmpless cmpltps
            cmpltss cmpneqps cmpneqss cmpnleps cmpnless cmpnltps cmpnltss
            cmpordps cmpordss cmpps cmpss cmpunordps cmpunordss comiss cvtpi2ps
            cvtps2pi cvtsi2ss cvtss2si cvttps2pi cvttss2si divps divss ldmxcsr
            maxps maxss minps minss movaps movhlps movhps movlhps movlps
            movmskps movntps movss movups mulps mulss orps rcpps rcpss rsqrtps
            rsqrtss shufps sqrtps sqrtss stmxcsr subps subss ucomiss unpckhps
            unpcklps xorps""" :
            [ SSE, None ],
            """maskmovq movntq pavgb pavgw pextrw pinsrw pmaxsw pmaxub pminsw
            pminub pmovmskb pmulhuw psadbw pshufw""" :
            [ MMXEXT, None ],
            """pf2iw pfnacc pfpnacc pi2fw pswapd""" :
            [ E3DN, None ], # 3DNow!
            """addpd addsd andnpd andpd clflush cmpeqpd cmpeqsd cmplepd cmplesd
            cmpltpd cmpltsd cmpneqpd cmpneqsd cmpnlepd cmpnlesd cmpnltpd
            cmpnltsd cmpordpd cmpordsd cmppd cmpunordpd cmpunordsd comisd
            cvtdq2pd cvtdq2ps cvtpd2dq cvtpd2pi cvtpd2ps cvtpi2pd cvtps2dq
            cvtps2pd cvtsd2si cvtsd2ss cvtsi2sd cvtss2sd cvttpd2dq cvttpd2pi
            cvttps2dq cvttsd2si divpd divsd maskmovdqu maxpd maxsd minpd minsd
            movapd movdq2q movdqa movdqu movhpd movlpd movmskpd movntdq movnti
            movntpd movq2dq movupd mulpd mulsd orpd paddq pmuludq pshufd
            pshufhw pshuflw pslldq psrldq psubq punpckhqdq punpcklqdq shufpd
            sqrtpd sqrtsd subpd subsd ucomisd unpckhpd unpcklpd xorpd""" :
            [ SSE2, None ],
            """addsubpd addsubps fisttp haddpd haddps hsubpd hsubps lddqu monitor
            movddup movshdup movsldup mwait""" :
            [ SSE3, None ],
            """pabsb pabsd pabsw palignr phaddd phaddsw phaddw phsubd phsubsw
            phsubw pmaddubsw pmulhrsw pshufb psignb psignd psignw""" :
            [ SSSE3, None ],
            """blendpd blendps blendvpd blendvps dppd dpps extractps insertps
            movntdqa mpsadbw packusdw pblendvb pblendw pcmpeqq pextrb pextrd
            pextrq phminposuw pinsrb pinsrd pinsrq pmaxsb pmaxsd pmaxud pmaxuw
            pminsb pminsd pminud pminuw pmovsxbd pmovsxbq pmovsxbw pmovsxdq
            pmovsxwd pmovsxwq pmovzxbd pmovzxbq pmovzxbw pmovzxdq pmovzxwd
            pmovzxwq pmuldq pmulld ptest roundpd roundps roundsd roundss""" :
            [ SSE41, None ],
            """crc32 pcmpestri pcmpestrm pcmpgtq pcmpistri pcmpistrm popcnt""" :
            [ SSE42, None ],
            """extrq insertq movntsd movntss""" :
            [ SSE4A, None ],
            """aesenc aesenclast aesdec aesdeclast aesimc aeskeygenassist""" :
            [ AES, None ],
            """pclmulhqhqdq pclmulhqlqdq pclmullqhqdq pclmullqlqdq pclmulqdq
            vaddpd vaddps vaddsd vaddss vaddsubpd vaddsubps vaesdec vaesdeclast
            vaesenc vaesenclast vaesimc vaeskeygenassist vandnpd vandnps vandpd
            vandps vblendpd vblendps vblendvpd vblendvps vbroadcastf128
            vbroadcastsd vbroadcastss vcmpeq_ospd vcmpeq_osps vcmpeq_ossd
            vcmpeq_osss vcmpeqpd vcmpeqps vcmpeqsd vcmpeqss vcmpeq_uqpd
            vcmpeq_uqps vcmpeq_uqsd vcmpeq_uqss vcmpeq_uspd vcmpeq_usps
            vcmpeq_ussd vcmpeq_usss vcmpfalse_oqpd vcmpfalse_oqps
            vcmpfalse_oqsd vcmpfalse_oqss vcmpfalse_ospd vcmpfalse_osps
            vcmpfalse_ossd vcmpfalse_osss vcmpfalsepd vcmpfalseps vcmpfalsesd
            vcmpfalsess vcmpge_oqpd vcmpge_oqps vcmpge_oqsd vcmpge_oqss
            vcmpge_ospd vcmpge_osps vcmpge_ossd vcmpge_osss vcmpgepd vcmpgeps
            vcmpgesd vcmpgess vcmpgt_oqpd vcmpgt_oqps vcmpgt_oqsd vcmpgt_oqss
            vcmpgt_ospd vcmpgt_osps vcmpgt_ossd vcmpgt_osss vcmpgtpd vcmpgtps
            vcmpgtsd vcmpgtss vcmple_oqpd vcmple_oqps vcmple_oqsd vcmple_oqss
            vcmple_ospd vcmple_osps vcmple_ossd vcmple_osss vcmplepd vcmpleps
            vcmplesd vcmpless vcmplt_oqpd vcmplt_oqps vcmplt_oqsd vcmplt_oqss
            vcmplt_ospd vcmplt_osps vcmplt_ossd vcmplt_osss vcmpltpd vcmpltps
            vcmpltsd vcmpltss vcmpneq_oqpd vcmpneq_oqps vcmpneq_oqsd
            vcmpneq_oqss vcmpneq_ospd vcmpneq_osps vcmpneq_ossd vcmpneq_osss
            vcmpneqpd vcmpneqps vcmpneqsd vcmpneqss vcmpneq_uqpd vcmpneq_uqps
            vcmpneq_uqsd vcmpneq_uqss vcmpneq_uspd vcmpneq_usps vcmpneq_ussd
            vcmpneq_usss vcmpngepd vcmpngeps vcmpngesd vcmpngess vcmpnge_uqpd
            vcmpnge_uqps vcmpnge_uqsd vcmpnge_uqss vcmpnge_uspd vcmpnge_usps
            vcmpnge_ussd vcmpnge_usss vcmpngtpd vcmpngtps vcmpngtsd vcmpngtss
            vcmpngt_uqpd vcmpngt_uqps vcmpngt_uqsd vcmpngt_uqss vcmpngt_uspd
            vcmpngt_usps vcmpngt_ussd vcmpngt_usss vcmpnlepd vcmpnleps
            vcmpnlesd vcmpnless vcmpnle_uqpd vcmpnle_uqps vcmpnle_uqsd
            vcmpnle_uqss vcmpnle_uspd vcmpnle_usps vcmpnle_ussd vcmpnle_usss
            vcmpnltpd vcmpnltps vcmpnltsd vcmpnltss vcmpnlt_uqpd vcmpnlt_uqps
            vcmpnlt_uqsd vcmpnlt_uqss vcmpnlt_uspd vcmpnlt_usps vcmpnlt_ussd
            vcmpnlt_usss vcmpordpd vcmpordps vcmpord_qpd vcmpord_qps
            vcmpord_qsd vcmpord_qss vcmpordsd vcmpord_spd vcmpord_sps vcmpordss
            vcmpord_ssd vcmpord_sss vcmppd vcmpps vcmpsd vcmpss vcmptruepd
            vcmptrueps vcmptruesd vcmptruess vcmptrue_uqpd vcmptrue_uqps
            vcmptrue_uqsd vcmptrue_uqss vcmptrue_uspd vcmptrue_usps
            vcmptrue_ussd vcmptrue_usss vcmpunordpd vcmpunordps vcmpunord_qpd
            vcmpunord_qps vcmpunord_qsd vcmpunord_qss vcmpunordsd vcmpunord_spd
            vcmpunord_sps vcmpunordss vcmpunord_ssd vcmpunord_sss vcomisd
            vcomiss vcvtdq2pd vcvtdq2ps vcvtpd2dq vcvtpd2ps vcvtps2dq vcvtps2pd
            vcvtsd2si vcvtsd2ss vcvtsi2sd vcvtsi2ss vcvtss2sd vcvtss2si
            vcvttpd2dq vcvttps2dq vcvttsd2si vcvttss2si vdivpd vdivps vdivsd
            vdivss vdppd vdpps vextractf128 vextractps vhaddpd vhaddps vhsubpd
            vhsubps vinsertf128 vinsertps vlddqu vldmxcsr vldqqu vmaskmovdqu
            vmaskmovpd vmaskmovps vmaxpd vmaxps vmaxsd vmaxss vminpd vminps
            vminsd vminss vmovapd vmovaps vmovd vmovddup vmovdqa vmovdqu
            vmovhlps vmovhpd vmovhps vmovlhps vmovlpd vmovlps vmovmskpd
            vmovmskps vmovntdq vmovntdqa vmovntpd vmovntps vmovntqq vmovq
            vmovqqa vmovqqu vmovsd vmovshdup vmovsldup vmovss vmovupd vmovups
            vmpsadbw vmulpd vmulps vmulsd vmulss vorpd vorps vpabsb vpabsd
            vpabsw vpackssdw vpacksswb vpackusdw vpackuswb vpaddb vpaddd vpaddq
            vpaddsb vpaddsw vpaddusb vpaddusw vpaddw vpalignr vpand vpandn
            vpavgb vpavgw vpblendvb vpblendw vpclmulhqhqdq vpclmulhqlqdq
            vpclmullqhqdq vpclmullqlqdq vpclmulqdq vpcmpeqb vpcmpeqd vpcmpeqq
            vpcmpeqw vpcmpestri vpcmpestrm vpcmpgtb vpcmpgtd vpcmpgtq vpcmpgtw
            vpcmpistri vpcmpistrm vperm2f128 vpermilpd vpermilps vpextrb
            vpextrd vpextrq vpextrw vphaddd vphaddsw vphaddw vphminposuw
            vphsubd vphsubsw vphsubw vpinsrb vpinsrd vpinsrq vpinsrw vpmaddubsw
            vpmaddwd vpmaxsb vpmaxsd vpmaxsw vpmaxub vpmaxud vpmaxuw vpminsb
            vpminsd vpminsw vpminub vpminud vpminuw vpmovmskb vpmovsxbd
            vpmovsxbq vpmovsxbw vpmovsxdq vpmovsxwd vpmovsxwq vpmovzxbd
            vpmovzxbq vpmovzxbw vpmovzxdq vpmovzxwd vpmovzxwq vpmuldq vpmulhrsw
            vpmulhuw vpmulhw vpmulld vpmullw vpmuludq vpor vpsadbw vpshufb
            vpshufd vpshufhw vpshuflw vpsignb vpsignd vpsignw vpslld vpslldq
            vpsllq vpsllw vpsrad vpsraw vpsrld vpsrldq vpsrlq vpsrlw vpsubb
            vpsubd vpsubq vpsubsb vpsubsw vpsubusb vpsubusw vpsubw vptest
            vpunpckhbw vpunpckhdq vpunpckhqdq vpunpckhwd vpunpcklbw vpunpckldq
            vpunpcklqdq vpunpcklwd vpxor vrcpps vrcpss vroundpd vroundps
            vroundsd vroundss vrsqrtps vrsqrtss vshufpd vshufps vsqrtpd vsqrtps
            vsqrtsd vsqrtss vstmxcsr vsubpd vsubps vsubsd vsubss vtestpd
            vtestps vucomisd vucomiss vunpckhpd vunpckhps vunpcklpd vunpcklps
            vxorpd vxorps vzeroall vzeroupper""" :
            [ AVX, None ],
            """vfmadd123pd vfmadd123ps vfmadd123sd vfmadd123ss vfmadd132pd
            vfmadd132ps vfmadd132sd vfmadd132ss vfmadd213pd vfmadd213ps
            vfmadd213sd vfmadd213ss vfmadd231pd vfmadd231ps vfmadd231sd
            vfmadd231ss vfmadd312pd vfmadd312ps vfmadd312sd vfmadd312ss
            vfmadd321pd vfmadd321ps vfmadd321sd vfmadd321ss vfmaddsub123pd
            vfmaddsub123ps vfmaddsub132pd vfmaddsub132ps vfmaddsub213pd
            vfmaddsub213ps vfmaddsub231pd vfmaddsub231ps vfmaddsub312pd
            vfmaddsub312ps vfmaddsub321pd vfmaddsub321ps vfmsub123pd
            vfmsub123ps vfmsub123sd vfmsub123ss vfmsub132pd vfmsub132ps
            vfmsub132sd vfmsub132ss vfmsub213pd vfmsub213ps vfmsub213sd
            vfmsub213ss vfmsub231pd vfmsub231ps vfmsub231sd vfmsub231ss
            vfmsub312pd vfmsub312ps vfmsub312sd vfmsub312ss vfmsub321pd
            vfmsub321ps vfmsub321sd vfmsub321ss vfmsubadd123pd vfmsubadd123ps
            vfmsubadd132pd vfmsubadd132ps vfmsubadd213pd vfmsubadd213ps
            vfmsubadd231pd vfmsubadd231ps vfmsubadd312pd vfmsubadd312ps
            vfmsubadd321pd vfmsubadd321ps vfnmadd123pd vfnmadd123ps
            vfnmadd123sd vfnmadd123ss vfnmadd132pd vfnmadd132ps vfnmadd132sd
            vfnmadd132ss vfnmadd213pd vfnmadd213ps vfnmadd213sd vfnmadd213ss
            vfnmadd231pd vfnmadd231ps vfnmadd231sd vfnmadd231ss vfnmadd312pd
            vfnmadd312ps vfnmadd312sd vfnmadd312ss vfnmadd321pd vfnmadd321ps
            vfnmadd321sd vfnmadd321ss vfnmsub123pd vfnmsub123ps vfnmsub123sd
            vfnmsub123ss vfnmsub132pd vfnmsub132ps vfnmsub132sd vfnmsub132ss
            vfnmsub213pd vfnmsub213ps vfnmsub213sd vfnmsub213ss vfnmsub231pd
            vfnmsub231ps vfnmsub231sd vfnmsub231ss vfnmsub312pd vfnmsub312ps
            vfnmsub312sd vfnmsub312ss vfnmsub321pd vfnmsub321ps vfnmsub321sd
            vfnmsub321ss""" :
            [ FMA, None ],
            """vfmaddpd vfmaddps vfmaddsd vfmaddss vfmaddsubpd vfmaddsubps
            vfmsubaddpd vfmsubaddps vfmsubpd vfmsubps vfmsubsd vfmsubss
            vfnmaddpd vfnmaddps vfnmaddsd vfnmaddss vfnmsubpd vfnmsubps
            vfnmsubsd vfnmsubss vfrczpd vfrczps vfrczsd vfrczss vpcmov vpcomb
            vpcomd vpcomq vpcomub vpcomud vpcomuq vpcomuw vpcomw vphaddbd
            vphaddbq vphaddbw vphadddq vphaddubd vphaddubq vphaddubw vphaddudq
            vphadduwd vphadduwq vphaddwd vphaddwq vphsubbw vphsubdq vphsubwd
            vpmacsdd vpmacsdqh vpmacsdql vpmacssdd vpmacssdqh vpmacssdql
            vpmacsswd vpmacssww vpmacswd vpmacsww vpmadcsswd vpmadcswd vpperm
            vprotb vprotd vprotq vprotw vpshab vpshad vpshaq vpshaw vpshlb
            vpshld vpshlq vpshlw""" :
            [ FMA4, None ],
            """cpuid""" :
            [ CPUID, None ]
    }

    # key => instruction
    # value => array of category and description
    lookup_table = dict()


    @staticmethod
    def init_instruction_table():
        for key, value in InstructionCategory.DBn.items():
            for instruction in key.split():
                InstructionCategory.lookup_table[instruction] = [value[0], value[1]]


    @staticmethod
    def guess(instructon):
        if instructon in InstructionCategory.lookup_table:
            return InstructionCategory.lookup_table[instructon][0]
        return InstructionCategory.UNKNOWN


    @staticmethod
    def str(cat):
        if cat == InstructionCategory.UNKNOWN: return "unknown"

        if cat == InstructionCategory.DATA_TRANSFER: return "DATA_TRANSFER"
        if cat == InstructionCategory.BINARY_ARITHMETIC: return "BINARY_ARITHMETIC"
        if cat == InstructionCategory.DECIMAL_ARITHMETIC: return "DECIMAL_ARITHMETIC"
        if cat == InstructionCategory.LOGICAL: return "LOGICAL"
        if cat == InstructionCategory.SHIFT_ROTATE: return "SHIFT_ROTATE"
        if cat == InstructionCategory.BIT_BYTE: return "BIT_BYTE"
        if cat == InstructionCategory.CONTROL_TRANSFER: return "CONTROL_TRANSFER"
        if cat == InstructionCategory.STRING: return "STRING"
        if cat == InstructionCategory.FLAG_CONTROL: return "FLAG_CONTROL"
        if cat == InstructionCategory.SEGMENT_REGISTER: return "SEGMENT_REGISTER"
        if cat == InstructionCategory.MISC: return "MISC"
        if cat == InstructionCategory.DATA_TRANSFER: return "DATA_TRANSFER"
        if cat == InstructionCategory.FLOATING_POINT: return "FLOATING_POINT"
        if cat == InstructionCategory.SYSTEM: return "SYSTEM"

        if cat == InstructionCategory.SIMD: return "SIMD"
        if cat == InstructionCategory.MMX: return "MMX"
        if cat == InstructionCategory.SSE: return "SSE"
        if cat == InstructionCategory.E3DN: return "E3DN"
        if cat == InstructionCategory.SSE2: return "SSE2"
        if cat == InstructionCategory.SSE3: return "SSE3"
        if cat == InstructionCategory.SSSE3: return "SSSE3"
        if cat == InstructionCategory.SSE41: return "SSE41"
        if cat == InstructionCategory.SSE42: return "SSE42"
        if cat == InstructionCategory.SSE4A: return "SSE4A"
        if cat == InstructionCategory.AES: return "AES"
        if cat == InstructionCategory.AVX: return "AVX"
        if cat == InstructionCategory.FMA: return "FMA"
        if cat == InstructionCategory.FMA4: return "FMA4"
        if cat == InstructionCategory.CPUID: return "CPUID"
        if cat == InstructionCategory.MMXEXT: return "MMXEXT"
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
        self.type  = b_type
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
            raise Exception("Line wrapped:\n%s\n" % (line))


    def parse_line(self, line, context):
        # 404e52:   e8 31 c2 ff ff          callq  401088 <_init>
        ret = dict()
        match = re.search(r'([\da-f]+):\s+((?:[0-9a-f]{2} )+)\s+(.*)', line)
        if not match:
            # Special case overlong wrapped in two lines:
            #  4046c7:       48 ba cf f7 53 e3 a5    movabs $0x20c49ba5e353f7cf,%rdx
            #  4046ce:       9b c4 20
            #self.is_wrapped_line_update(line)
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
        cmd = 'objdump -d --insn-width=16 %s' % (filename)
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
        if statinfo.st_size > 1000000:
            self.caller.verbose("File larger then 1MByte, analysis may take some time\n")

        self.process(self.args.filename)



class FunctionAnatomyAnalyzer(Common):

    def __init__(self):
        self.func_excluder = FunctionExcluder()
        self.parse_local_options()
        self.db = dict()
        self.len_longest_filename = 10
        self.len_longest_size = 4


    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.usage = "InstructionAnalyzer"
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                          action="store_true", help="show verbose")
        parser.add_option( "-x", "--no-exclude", dest="no_exclude", default=False,
                action="store_true", help="do *not* exclude some glibc/gcc helper"
                "runtime functions like __init _start or _do_global_dtors_aux")

        self.opts, args = parser.parse_args(sys.argv[0:])

        if len(args) != 3:
            self.err("No <binary> argument given, exiting\n")
            sys.exit(1)

        if self.opts.no_exclude:
            # empty list means there will never be a match
            self.func_excluder = None

        self.verbose("Analyze binary: %s\n" % (sys.argv[-1]))
        self.opts.filename = args[-1]


    def run(self):
        self.parser = Parser(self.opts)
        self.parser.run(self)
        self.show()


    def process_function_pro_epi_logue(self, context, atom, mnemonic_db):
        if mnemonic_db['cnt'] < 4:
            # we capture the first 10 instructions per functions
            mnemonic_db[mnemonic_db['cnt']] = atom.mnemonic
            mnemonic_db['captured'] += 1
        # this will overwriten each time, at the end this entry will hold
        # the last mnemonic for the function
        mnemonic_db['-1'] = atom.mnemonic
        mnemonic_db['cnt'] += 1

    def process(self, context, atom):
        if self.func_excluder and self.func_excluder.is_excluded(context.function_name):
            return
        self.len_longest_filename = max(len(context.function_name), self.len_longest_filename)
        if not context.function_name in self.db:
            self.db[context.function_name] = dict()
            self.db[context.function_name]['start'] = \
                    context.function_start_address
            self.db[context.function_name]['end'] = \
                    context.function_start_address + atom.opcode_len
            self.db[context.function_name]['size'] = \
                    self.db[context.function_name]['end'] - self.db[context.function_name]['start']
            self.db[context.function_name]['mnemonic'] = dict()
            self.db[context.function_name]['mnemonic']['cnt'] = 0
            self.db[context.function_name]['mnemonic']['captured'] = 0
            self.process_function_pro_epi_logue(context, atom, self.db[context.function_name]['mnemonic'])
            return

        self.db[context.function_name]['end'] += atom.opcode_len
        self.db[context.function_name]['size'] = \
                self.db[context.function_name]['end'] - self.db[context.function_name]['start']
        self.len_longest_size = max(len(str(self.db[context.function_name]['size'])), self.len_longest_size)
        # last mnemonic in function
        self.process_function_pro_epi_logue(context, atom, self.db[context.function_name]['mnemonic'])


    def show(self, json=False):
        if json:
            self.show_json()
        else:
            self.show_human()


    def show_human(self):
        # Some overall information about functions
        # Number of Functions, average len, min length, max length, etc
        self.msg("Functions Size:\n\n")
        fmt = "%%%d.%ds: %%%dd byte  [start: 0x%%x, end: 0x%%x]\n" % \
                (self.len_longest_filename, self.len_longest_filename, self.len_longest_size)
        for key in sorted(self.db.items(), key=lambda item: item[1]['size'], reverse=True):
            self.msg(fmt % (key[0], key[1]['size'], key[1]['start'], key[1]['end']))

        # Function Mnemonic Signature Overview
        if self.opts.verbose:
            for key, value in self.db.items():
                self.msg("%s:\n" % (key))
                for i in range(self.db[key]['mnemonic']['captured']):
                    self.msg("\t%d %s\n" % (i, self.db[key]['mnemonic'][i]))


    def show_json(self):
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
        self.msg("    Number Instructions: %d\n" % (overall))
        self.msg("    Number different Instructions: %d\n" % (len(self.instructions.keys())))
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



class StackAnalyzer(Common):

    def __init__(self):
        self.func_excluder = FunctionExcluder()
        self.db = dict()
        self.all_function_db = dict()
        self.parse_local_options()


    def parse_local_options(self):
        parser = optparse.OptionParser()
        parser.usage = "stack"
        parser.add_option( "-x", "--no-exclude", dest="no_exclude", default=False,
                action="store_true", help="do *not* exclude some glibc/gcc helper"
                "runtime functions like __init _start or _do_global_dtors_aux")
        parser.add_option( "-v", "--verbose", dest="verbose", default=False,
                action="store_true", help="show verbose")
        parser.add_option( "-g", "--graphs", dest="generate_graphs", default=False,
                action="store_true", help="generate SVG graphs")

        self.opts, args = parser.parse_args(sys.argv[0:])

        if len(args) != 3:
            self.err("No <binary> argument given, exiting\n")
            sys.exit(1)

        if self.opts.no_exclude:
            # empty list means there will never be a match
            self.func_excluder = None

        self.verbose("Analyze binary: %s\n" % (sys.argv[-1]))
        self.opts.filename = args[-1]


    def run(self):
        self.parser = Parser(self.opts)
        self.parser.run(self)
        self.output()


    def check_stack_mangling_op(self, context, atom, func_db):
        # return true if function is mangling with frame
        # if size is unknown 0 is returned, e.g. LSAs
        # LSAs are not covered here, e.g.
        # ffffffff8134a35a:       48 29 d4                sub    %rdx,%rsp
        if atom.type == BinaryAtom.TYPE_2 and atom.mnemonic == 'sub' and atom.dst == '%rsp':
            if atom.src.startswith('$'):
                val = int(atom.src[1:], 16)
                if val > 0xf0000000:
                    # really rare path for sub, but still possible
                    # see next "val > 0xf0000000" statement for an in detail description
                    s1 = ctypes.c_uint32(-val)
                    s1.value += ctypes.c_uint32(0x80000000).value
                    s1.value += ctypes.c_uint32(0x80000000).value
                    retobj = RetObj(RetObj.STATIC)
                    retobj.val = s1.value
                    return retobj
                else:
                    retobj = RetObj(RetObj.STATIC)
                    retobj.val = val
                    return retobj
            else:
                # 48 29 c4                sub    %rax,%rsp
                if atom.src in ['%rcx', '%rax', '%rdx', '%r8', '%rdi', '%r11']:
                    retobj = RetObj(RetObj.DYNAMIC)
                    retobj.val = 0
                    retobj.register = atom.src
                    return retobj
                else:
                    raise Exception("Unknown encoding here:\n%s\nIn: \"%s\"" %
                            (atom.line, context.function_name))
        elif atom.type == BinaryAtom.TYPE_2 and atom.mnemonic == 'add' and atom.dst == '%rsp':
            # 48 83 e4 f0           and    $0xfffffffffffffff0,%rsp
            # This is smart GCC behavior:
            # when stack frame of e.g. 128 byte is required is does not
            # subtract 128 from %rsp, instead  adds -128 byte which can
            # be encoded as an immediate (imm8) instruction and is thus
            # shorter as the sub 128 counterpart.
            if not atom.src.startswith('$'):
                # 48 29 c4                add    %r11,%rsp
                if atom.src in ['%rcx', '%rax', '%rdx', '%r8', '%rdi', '%r11']:
                    retobj = RetObj(RetObj.DYNAMIC)
                    retobj.val = 0
                    retobj.register = atom.src
                    return retobj
                else:
                    raise Exception("Unknown encoding here:\n%s\nIn: \"%s\"" %
                            (atom.line, context.function_name))
            else:
                val = int(atom.src[1:], 16)
                if val > 0xf0000000:
                    s1 = ctypes.c_uint32(-val)
                    s1.value += ctypes.c_uint32(0x80000000).value
                    s1.value += ctypes.c_uint32(0x80000000).value
                    retobj = RetObj(RetObj.STATIC)
                    retobj.val = s1.value
                    return retobj

        # default case for non stack related instructions
        return None


    def process(self, context, atom):
        if self.func_excluder and self.func_excluder.is_excluded(context.function_name):
            return
        if context.function_name not in self.all_function_db:
            self.all_function_db[context.function_name] = True
        if context.function_name in self.db:
            func_db = self.db[context.function_name]
        else:
            func_db = dict()
            func_db['stack-usage-no'] = 0
        ret = self.check_stack_mangling_op(context, atom, func_db)
        if not ret:
            return
        # add or re-add to global database
        self.db[context.function_name] = func_db
        func_db['stack-usage-no'] += 1
        label = 'stack-usage-%d' % (func_db['stack-usage-no'])
        func_db[label] = ret.val


    def percent(self, i, j):
        if j == 0:
            return 0.0
        return (float(j) / float(i)) * 100.0


    def output_bucket_historgram(self, sorted_data, overall):
        sys.stdout.write("Stack Usage Histogram:\n")
        d = dict()
        for i in range(3, 14):
            exp = 2 ** i
            d[exp] = 0
        
        for data in sorted_data:
            if data[1] == 0:
                continue
            for i in range(3, 14):
                exp = 2 ** i
                if data[1] <= exp:
                    d[exp] += 1
                    break

        if self.opts.generate_graphs:
            file_out_name = 'function-stack-histogram'
            l = pygal.style.LightStyle
            l.foreground='black'
            l.background='white'
            l.plot_background='white'
            pie_chart = pygal.Pie(fill=True, style=l)
            pie_chart.title = 'Stack Memory Allocation Histogram'

        for i in range(3, 14):
            exp = 2 ** i
            percent = self.percent(overall, d[exp])
            sys.stdout.write("%-5d %6d    (%5.1f%% )\n" % (exp, d[exp], percent))
            if self.opts.generate_graphs and d[exp] > 0:
                pie_chart.add("%s byte" % (str(exp)), d[exp])
        sys.stdout.write("\n")

        if self.opts.generate_graphs:
            pie_chart.render_to_file('%s.svg' % (file_out_name))
            sys.stderr.write("# created graph file:  %s.svg\n" % (file_out_name))
            os.system("inkscape --export-png=%s.png %s.svg 1>/dev/null 2>&1" %
                    (file_out_name, file_out_name))
            sys.stderr.write("# created graph file:  %s.png\n" % (file_out_name))


    def graph_with_vs_without(self, no_functions_with, no_functions_without):
        file_out_name = 'function-stack-allocation'
        l = pygal.style.LightStyle
        l.foreground='black'
        l.background='white'
        l.plot_background='white'

        pie_chart = pygal.Pie(fill=True, style=l)
        pie_chart.title = 'Stack Memory Allocation per Function'
        pie_chart.add('With Stack Allocation', no_functions_with)
        pie_chart.add('Without Stack Allocation', no_functions_without)
        pie_chart.render_to_file('%s.svg' % (file_out_name))
        sys.stderr.write("# created graph file:  %s.svg\n" % (file_out_name))
        os.system("inkscape --export-png=%s.png %s.svg 1>/dev/null 2>&1" %
                (file_out_name, file_out_name))
        sys.stderr.write("# created graph file:  %s.png\n" % (file_out_name))


    def output_with_vs_without(self, no_functions, no_functions_with, no_functions_without):
        percent_w_stack = self.percent(no_functions, no_functions_with)
        sys.stdout.write("Function with stack utilization: %5d   (%4.0f%% )\n" %
                (no_functions_with, percent_w_stack))
        percent_wo_stack = self.percent(no_functions, no_functions_without)
        sys.stdout.write("Function w/o stack utilization:  %5d   (%4.0f%% )\n" %
                (no_functions_without, percent_wo_stack))
        sys.stdout.write("\n")

        if self.opts.generate_graphs:
            self.graph_with_vs_without(no_functions_with, no_functions_without)


    def output(self):
        no_functions = len(self.all_function_db)
        function_with_stack = len(self.db)
        function_without_stack = no_functions - function_with_stack

        self.output_with_vs_without(no_functions, function_with_stack, function_without_stack)

        # We first sort the entries here, this is somewhat not
        # Pythonlikelambda but opens the possibility to do a more
        # advanced sorting
        sorted_data = []
        for function_name, value in self.db.items():
            cnt =  self.db[function_name]['stack-usage-no']
            nested = ""
            for i in range(cnt - 1):
                label = 'stack-usage-%d' % (i + 2)
                d = self.db[function_name][label]
                if d == 0:
                    nested += "Dynamic "
                else:
                    nested += str(d) + " "
            if nested == '':
                nested = "-"
            sorted_data.append([function_name, int(self.db[function_name]['stack-usage-1']), nested])

        sorted_data.sort(reverse=True, key=lambda d: d[1])
        self.output_bucket_historgram(sorted_data, function_with_stack)
        sys.stdout.write("%-40.40s %5.5s   %25.25s\n" % ("Function Name", "Byte", "Multi Level Allocation"))
        for data in sorted_data:
            if data[1] == 0:
                sys.stdout.write("%-40.40s Dynamic   %-20.20s\n" % (data[0], data[2]))
            else:
                sys.stdout.write("%-40.40s %5.d      %-20.20s\n" % (data[0], data[1], data[2]))




class MachineCodeAnalyzer:

    modes = {
       "function-anatomy":     [ "FunctionAnatomyAnalyzer", "Function anatomy information" ],
       "instruction-analyzer": [ "InstructionAnalyzer",     "Information about instructions" ],
       "stack":                [ "StackAnalyzer",           "Stack usage analyzer" ]
            }


    def __init__(self):
        InstructionCategory.init_instruction_table()
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
