# Instruction and Opcode Analyzer #

A two pass code analyzer for x86 and x86\_64, requires debug symbols for full
analyze capabilities.

## Modules ##

### Function Local Branch and Jump Analyzer ###

Analyze local jump instructions. "Local" refers to jumps within the function
space - function calls and long jumps are not analyzed by this module.

Following data calcalated:

- Jump analyzer
  - Number of jumps
  - Average jump distance in bytes
  - Minimal jump distance in bytes
  - Maximal jump distance in bytes
  - Histogram of jumps
- Forward jump analyzer
  - Number of jumps
  - Average jump distance in bytes
  - Minimal jump distance in bytes
  - Maximal jump distance in bytes
  - Histogram of jumps
- Number of backward jumps per function
  - Number of jumps
  - Average jump distance in bytes
  - Minimal jump distance in bytes
  - Maximal jump distance in bytes
  - Histogram of jumps



#### Usage ####

```
# instruction-layout-analyzer --function-branch-jump <binary>
```

### Function Anatomy Analyzer ###

Started as an internal module for other modules this module provides
information about the function start and end addresses, the size of a function
and the number of functions.


#### Usage ####

```
# instruction-layout-analyzer --function-anatomy <binary>
```


# FAQ #

## Sometimes instruction analyzer and readelf differs from the code size - why? ##

Consider the following end of an function:


```gas
405021:       5d                      pop    %rbp
405022:       c3                      retq
405023:       66 2e 0f 1f 84 00 00    nopw   %cs:0x0(%rax,%rax,1)
40502a:       00 00 00
40502d:       0f 1f 00                nopl   (%rax)
```

What you see here are alignmend padding in form of NOP instructions (13 byte).
The code actual function end at retq instruction. The subsequent code is now
aligned at 0x405030, better for cachelines, etc.  The question now is: should
the instruction analayzer account the padding instructions or not? Feel free
and verify code with

```
readelf -s <binary>
```

NOPs are mostly generated and added by GAS (GNU assembler if using GCC). There
are other ways as well to decode NOPs:  xchg %ax,%ax (two byte), leal
0(%esi),%esi (three byte).

Last note: the assembler should always pad with as less instruction as possible
to relax CPU prefetcher and subsequent CPU logic.


# JSON to Chart.js Converter #

To generate charts a helper script comes bundled with instruction-layout-analyzer.
