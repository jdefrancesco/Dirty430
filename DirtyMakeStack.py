# -*- coding: utf-8 -*-
# DirtyMakeStack.py – Safe version

from java.math import BigInteger
from ghidra.program.model.lang import RegisterValue
from ghidra.program.model.symbol import SourceType

RAM_START     = 0x1C00
RAM_END       = 0x5BFF
VEC_MIN       = 0xFF80
VEC_MAX       = 0xFFFE      # ✅ highest VALID vector (even-aligned)
RESET_SP_ADDR = 0xFFFC
RESET_PC_ADDR = 0xFFFE

LABEL_ISR_TARGETS = True
SET_PC_CONTEXT    = False

def toAddr(x):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x)

def read_word_le(off):
    """
    SAFE little-endian 16-bit read.
    Returns None if address invalid, odd, uninitialized, or at 0xFFFF.
    """
    try:
        if off & 1:
            return None
        mem = currentProgram.getMemory()
        a = toAddr(off)
        if not mem.contains(a):
            return None
        block = mem.getBlock(a)
        if block is None or not block.isInitialized():
            return None
        if off + 1 > block.getEnd().getOffset():
            return None
        return int(mem.getShort(a) & 0xFFFF)
    except:
        return None

def ensure_stack_block():
    mem = currentProgram.getMemory()
    blk = mem.getBlock("STACK")
    if blk:
        blk.setPermissions(True, True, False)
        return blk
    for b in mem.getBlocks():
        bs = b.getStart().getOffset()
        be = b.getEnd().getOffset()
        if not (RAM_END < bs or RAM_START > be):
            b.setPermissions(True, True, False)
            try: b.setName("STACK")
            except: pass
            return b
    try:
        size = RAM_END - RAM_START + 1
        blk = mem.createUninitializedBlock("STACK", toAddr(RAM_START), size, False)
        blk.setPermissions(True, True, False)
        return blk
    except:
        return None

def set_sp(sp_val):
    reg = currentProgram.getLanguage().getRegister("SP") or currentProgram.getLanguage().getRegister("R1")
    ctx = currentProgram.getProgramContext()
    rv = RegisterValue(reg, BigInteger.valueOf(sp_val))
    ctx.setRegisterValue(currentProgram.getMinAddress(), currentProgram.getMaxAddress(), rv)

def safe_label(addr, name):
    st = currentProgram.getSymbolTable()
    a = toAddr(addr)
    try:
        for s in st.getSymbols(a):
            if s.getName() == name:
                return
        st.createLabel(a, name, SourceType.USER_DEFINED)
    except:
        try: st.createLabel(a, name + "_%04X" % addr, SourceType.USER_DEFINED)
        except: pass

def set_entry(pc):
    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()
    a = toAddr(pc)
    safe_label(pc, "reset_handler")
    try: st.addExternalEntryPoint(a)
    except: pass
    if not fm.getFunctionAt(a):
        try: fm.createFunction(a, "reset_handler")
        except: pass

def label_vectors_and_targets():
    vector_names = {
        0xFFFE: "V_RESET",
        0xFFFC: "V_RESET_SP",
        0xFFFA: "V_SYSNMI",
        0xFFF8: "V_USERNMI",
        0xFFF6: "V_TB0_CCR0",
        0xFFF4: "V_TB0_TBIV",
        0xFFF2: "V_WDT",
        0xFFF0: "V_USCI_A0",
        0xFFEE: "V_USCI_B0",
        0xFFEC: "V_ADC12_A",
        0xFFEA: "V_TA0_CCR0",
        0xFFE8: "V_TA0_TAIV",
        0xFFE6: "V_USCI_A2",
        0xFFE4: "V_USCI_B2",
        0xFFE2: "V_DMA",
        0xFFE0: "V_TA1_CCR0",
        0xFFDE: "V_TA1_TAIV",
        0xFFDC: "V_PORT1",
        0xFFDA: "V_USCI_A1",
        0xFFD8: "V_USCI_B1",
        0xFFD6: "V_USCI_A3",
        0xFFD4: "V_USCI_B3",
        0xFFD2: "V_PORT2",
        0xFFD0: "V_RTC_A",
    }

    off = VEC_MAX  # ✅ 0xFFFE, not 0xFFFF
    while off >= VEC_MIN:
        name = vector_names.get(off, "V_RESERVED_%04X" % off)
        safe_label(off, name)

        if LABEL_ISR_TARGETS and off != RESET_SP_ADDR:
            tgt = read_word_le(off)
            if tgt not in (None, 0x0000, 0xFFFF) and currentProgram.getMemory().contains(toAddr(tgt)):
                safe_label(tgt, "ISR_" + name.replace("V_", ""))
        off -= 2

def main():
    print("=== Dirty430 --- MSP430F5438 ===")
    ensure_stack_block()

    sp = read_word_le(RESET_SP_ADDR)
    if sp is None or sp in (0x0000, 0xFFFF):
        sp = RAM_END
        print("[!] SP invalid, fallback 0x%04X" % sp)
    else:
        print("[D430] SP = 0x%04X" % sp)
    set_sp(sp)

    pc = read_word_le(RESET_PC_ADDR)
    if pc not in (None, 0x0000, 0xFFFF):
        print("[D430] PC = 0x%04X" % pc)
        set_entry(pc)
    else:
        print("[!] Reset PC invalid")

    label_vectors_and_targets()
    print("[D430] Done. Re-run Auto Analyze.")

if __name__ == "__main__":
    main()