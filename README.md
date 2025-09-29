# Dirty430

## Ghidra script to make `MSP430` reversing a bit less abrasive!

Ghidra plugin to analyze and clean up `msp430f5438` firmware binaries.

The plugin has two simple phases:

1. **Post Analyze Phase**: This phase identifies and marks the vector table found in `MSP430F5438` firmware binaries.
    It also identifies and marks the interrupt service routines (ISRs) associated with the vectors in the table.
2. **Cleanup Phase**: This simply marks memory mapped registers (MMRs) and other special function registers (SFRs) in the disassembly.

**NOTE:** This plugin is hardcoded for the `MSP430f5438` microcontroller. However, it can be easily adapted to other `MSP430` variants by modifying the relevant parameters in the code.

The following sources can be references: <ADD TOOLKIT>

## Post Decompile Phase Optimizations.

The cleaning of Decompiled code can go a long way for the `MSP430`:
We attempt to apply the following to decompilation output:

  - MUL/DIV SimplIfications (No hardware support on msp430s)
  - Bitmask macro cleanup
  - Switch recovery
  - Struct detection
  - Peripheral register renaming (if mapping provided)
  - Constant folding


