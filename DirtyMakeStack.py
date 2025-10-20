# -*- coding: utf-8 -*-
# DirtyMakeStack.py
# Creates or reuses a STACK block, sets SP (Stack Pointer) value in Program Context.
# Works with MSP430 targets where SP is R1 and stack grows downward.
#
# @author J. DeFrancesco
# @category Memory

from java.math import BigInteger
from ghidra.program.model.lang import RegisterValue

STACK_START = 0x01C00
STACK_END   = 0x05BFF

def toAddr(x):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x)

def ensure_stack_block(start, end):
    mem = currentProgram.getMemory()

    existing = mem.getBlock("STACK")
    if existing:
        print("[=] STACK block already exists:", existing.getStart(), "-", existing.getEnd())
        return existing

    # Detect overlaps with any RAM or other blocks
    for b in mem.getBlocks():
        b_start = b.getStart().getOffset()
        b_end = b.getEnd().getOffset()
        if not (end < b_start or start > b_end):
            print("[!] Reusing overlapping block '%s' (%s - %s)" % (b.getName(), b.getStart(), b.getEnd()))
            return b

    # Create new stack block if safe
    try:
        size = end - start + 1
        blk = mem.createUninitializedBlock("STACK", toAddr(start), size, False)
        blk.setPermissions(True, True, False)
        print("[+] Created STACK block: 0x%05X - 0x%05X" % (start, end))
        return blk
    except Exception as e:
        print("[!] Failed to create STACK block:", e)
        return None

def set_sp_register_value(sp_value):
    lang = currentProgram.getLanguage()
    reg = lang.getRegister("SP") or lang.getRegister("R1")

    if reg is None:
        print("[!] Could not find SP or R1 register in language")
        return False

    ctx = currentProgram.getProgramContext()
    minA = currentProgram.getMinAddress()
    maxA = currentProgram.getMaxAddress()

    try:
        # Create proper RegisterValue
        rv = RegisterValue(reg, BigInteger.valueOf(sp_value))
        ctx.setRegisterValue(minA, maxA, rv)
        print("[+] Successfully set %s = 0x%05X for %s - %s" % (reg.getName(), sp_value, minA, maxA))
        return True
    except Exception as e:
        print("[!] Failed to set SP:", e)
        return False

def main():
    print("=== DirtyMakeStack ===")
    stack_block = ensure_stack_block(STACK_START, STACK_END)
    if not stack_block:
        print("[!] Aborting — no valid stack block found.")
        return

    # MSP430 stack grows downward, top = highest RAM address
    stack_top = stack_block.getEnd().getOffset()
    print("[=] Using stack top: 0x%05X" % stack_top)

    if set_sp_register_value(stack_top):
        print("[D430] Done. Re-run Auto Analysis for best results.")
    else:
        print("[!] SP could not be set automatically — set manually if needed.")

if __name__ == '__main__':
    main()
