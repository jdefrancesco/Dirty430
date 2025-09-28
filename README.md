# Dirty430
<<<<<<< HEAD
Ghidra script for making RAW MSP bins cleaner.
=======

Ghidra plugin to analayze and clean up `msp430f5438` firmware binarie..

The plugin has two simple phases:

1. **Post Analyze Phase**: This phase identifies and marks the vector table found in `MSP430F5438` firmware binaries.
    It also identifies and marks the interrupt service routines (ISRs) associated with the vectors in the table.
2. **Cleanup Phase**: This simply marks memory mapped registers (MMRs) and other special function registers (SFRs) in the disassembly.

**NOTE:** This plugin is hardcoded for the `msp430f5438` microcontroller. However, it can be easily adapted to other `msp430` variants by modifying the relevant parameters in the code.


## Post Decompile Phase Optimizations.


>>>>>>> 7e17a1d (Commited a README.md)
