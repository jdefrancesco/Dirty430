# DirtyMakeStack.py
# Creates a STACK block and sets SP register value in program context
# then suggests re-running Auto Analysis.
#
# Edit STACK_START / STACK_END if your target uses different RAM ranges.

#@author J. DeFrancesco
#@category Memory


from java.math import BigInteger
from ghidra.program.model.address import Address
from ghidra.program.model.mem import MemoryBlockType

# Adjust these defaults if your MSP430 variant has different RAM
STACK_START = 0x01C00
STACK_END   = 0x05BFF

def toAddr(x):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x)

def ensure_stack_block(start, end):
    mem = currentProgram.getMemory()
    # If block named STACK already exists, return it
    try:
        b = mem.getBlock("STACK")
        if b:
            print("[=] STACK block already exists: %s - %s" % (b.getStart(), b.getEnd()))
            return b
    except Exception:
        pass
    # If some block already covers the range, try to reuse or create a differently named block
    try:
        start_addr = toAddr(start)
        size = end - start + 1
        blk = mem.createUninitializedBlock("STACK", start_addr, size, False)
        blk.setPermissions(True, True, False)
        print("[+] Created STACK block 0x%05X - 0x%05X" % (start, end))
        return blk
    except Exception as e:
        # fallback: find a block that intersects and return it (but warn)
        for b in mem.getBlocks():
            bs = b.getStart().getOffset()
            be = b.getEnd().getOffset()
            if not (end < bs or start > be):
                print("[!] Could not create STACK block; using existing block '%s' (%s-%s)" % (b.getName(), b.getStart(), b.getEnd()))
                return b
        print("[!] Failed to create or find suitable STACK block: %s" % str(e))
        return None

def set_sp_register_value(sp_value):
    # Set SP register value in program context across the whole program address range
    lang = currentProgram.getLanguage()
    # Common names for SP: "SP" or "R1" depending on language; try both
    reg = lang.getRegister("SP")
    if reg is None:
        reg = lang.getRegister("R1")
    if reg is None:
        print("[!] Could not find SP register in language: %s" % lang.getProcessor().toString())
        return False

    ctx = currentProgram.getProgramContext()
    minA = currentProgram.getMinAddress()
    maxA = currentProgram.getMaxAddress()
    try:
        bi = BigInteger.valueOf(long(sp_value))
        ctx.setValue(reg, bi, minA, maxA)
        print("[+] Set SP register (%s) to 0x%05X for address range %s - %s" % (reg.getName(), sp_value, minA, maxA))
        return True
    except Exception as e:
        print("[!] Failed to set SP register value: %s" % str(e))
        return False

def main():
    print("=== create_stack_and_set_sp ===")
    mem = currentProgram.getMemory()

    # ensure a stack block exists (or reuse an intersecting block)
    stack_block = ensure_stack_block(STACK_START, STACK_END)
    if stack_block is None:
        print("[!] No STACK block available; aborting")
        return

    # MSP430 SP grows down, so initial SP usually points near the highest RAM address.
    stack_top = stack_block.getEnd().getOffset()
    print("[=] Using stack top 0x%05X as SP initial value" % stack_top)

    # set SP register value in the program context
    ok = set_sp_register_value(stack_top)
    if not ok:
        print("[!] Could not set SP; you may need to set this manually in Program Context")

    print("[D430] Done. Re-run analysis")

if __name__ == '__main__':
    main()
