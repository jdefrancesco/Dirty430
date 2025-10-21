# Dirty430

## Ghidra script to make `MSP430` reversing a bit less abrasive!

Ghidra plugin to analyze and clean up `msp430f5438` firmware binaries.

The plugin does a couple helpful things:

* Creates correct memory map for MSP430F5438
* Labels SFR with comments to specify offsets
* Labels Interrupt Vector Table
* Sets SP from vector table.


**NOTE:** This plugin is hardcoded for the `MSP430f5438` microcontroller. However, it
an be easily adapted to other `MSP430` variants by modifying the relevant parameters in the code.


## FindCrypt

Use FindCrypt Ghidra plugin on github if available. This is a 
small Python script to look for crypto primitives in case FindCrypt doesn't want to behave. 
Will add more ciphers/constant heuristics eventually.