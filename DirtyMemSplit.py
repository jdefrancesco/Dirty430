# -*- coding: utf-8 -*-
# Dirty430 – MSP430F5438 Automatic Memory Split + SP/PC Init + Vector Labels
#
#  Splits raw firmware block into correct MSP430F5438 regions
#  Sets SP from 0xFFFC, PC from 0xFFFE (if valid)
#  Labels interrupt vectors and their ISRs
#

# @author J. DeFrancesco
# @category Dirty430

from java.math import BigInteger
from ghidra.program.model.lang import RegisterValue
from ghidra.program.model.symbol import SourceType

# Memory regions for MSP430F5438
REGIONS = [
    ("PERIPHERALS",   0x00000, 0x00FFF, "SFR + peripherals"),
    ("BSL_ROM",       0x01000, 0x017FF, "Bootloader ROM"),
    ("INFO_FLASH_D",  0x01800, 0x0187F, "Info Flash D"),
    ("INFO_FLASH_C",  0x01880, 0x018FF, "Info Flash C"),
    ("INFO_FLASH_B",  0x01900, 0x0197F, "Info Flash B"),
    ("INFO_FLASH_A",  0x01980, 0x019FF, "Info Flash A"),
    ("SRAM",          0x01C00, 0x05BFF, "Main RAM"),
    ("MAIN_FLASH_LO", 0x05C00, 0x0FF7F, "Main Flash lower"),
    ("INT_VECTORS",   0x0FF80, 0x0FFFF, "Interrupt vectors"),
    # Optional extended banks (only if firmware > 64KB)
    ("MAIN_FLASH_B1", 0x10000, 0x1FFFF, "Main Flash Bank1"),
    ("MAIN_FLASH_B2", 0x20000, 0x2FFFF, "Main Flash Bank2"),
    ("MAIN_FLASH_B3", 0x30000, 0x3FFFF, "Main Flash Bank3"),
    ("MAIN_FLASH_B4", 0x40000, 0x45BFF, "Main Flash Bank4"),
]

RESET_SP = 0xFFFC
RESET_PC = 0xFFFE
VEC_MIN  = 0x0FF80
VEC_MAX  = 0x0FFFF

VECTOR_NAMES = {
    0xFFFE: "RESET",
    0xFFFC: "INITIAL_SP",
    0xFFFA: "NMI",
    0xFFF8: "USER_NMI"
    # Others can be added here if known
}

def toAddr(off):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off)

def mem():
    return currentProgram.getMemory()

def split_block(start, end, name, comment):
    m = mem()
    a0 = toAddr(start)
    a1 = toAddr(end + 1)
    blk = m.getBlock(a0)
    if blk is None:
        return
    
    if blk.getStart().getOffset() < start:
        try: m.split(blk, a0)
        except: return
    
    blk = m.getBlock(a0)
    if blk and blk.getEnd().getOffset() > end:
        try: m.split(blk, a1)
        except: pass
    
    blk2 = m.getBlock(a0)
    if blk2:
        try: blk2.setName(name)
        except: pass
        blk2.setComment(comment)
        
        if name == "SRAM" or name == "PERIPHERALS":
            blk2.setPermissions(True, True, False)  # R/W
        else:
            blk2.setPermissions(True, False, True)  # R/X
        
        print("[D430] Region %-12s 0x%05X-0x%05X" % (name, start, end))

def rename_leftover():
    m = mem()
    for blk in m.getBlocks():
        if blk.getName().startswith("FLASH"):
            blk.setName("UNMAPPED_FLASH")
            blk.setPermissions(True, False, True)
            blk.setComment("Remaining firmware not in known map")
            print("[D430] Renamed leftover block -> UNMAPPED_FLASH")

def safe_word(off):
    try:
        val = mem().getShort(toAddr(off)) & 0xFFFF
        return val
    except:
        return None

def set_sp(pc_val):
    lang = currentProgram.getLanguage()
    reg = lang.getRegister("SP") or lang.getRegister("R1")
    if not reg:
        print("[!] No SP register found")
        return
    val = BigInteger.valueOf(pc_val)
    ctx = currentProgram.getProgramContext()
    ctx.setRegisterValue(currentProgram.getMinAddress(), currentProgram.getMaxAddress(), RegisterValue(reg, val))
    print("[D430] Set SP = 0x%04X" % pc_val)


def set_entry_point(pc_val):
    addr = toAddr(pc_val)
    st = currentProgram.getSymbolTable()
    fm = currentProgram.getFunctionManager()

    # Create/reset label
    try:
        st.createLabel(addr, "reset_handler", SourceType.USER_DEFINED)
    except:
        pass

    # Mark as program entry point
    try:
        st.addExternalEntryPoint(addr)
    except:
        pass

    # Create function at this address (Ghidra requires name, entry addr, body=None, sourceType)
    if fm.getFunctionAt(addr) is None:
        try:
            fm.createFunction("reset_handler", addr, None, SourceType.USER_DEFINED)
        except:
            print("[!] Could not create function at 0x%04X" % pc_val)

    print("[D430] Set reset handler at 0x%04X" % pc_val)

def label_vectors():
    off = VEC_MAX
    while off >= VEC_MIN:
        name = VECTOR_NAMES.get(off, "VEC_%04X" % off)
        addr = toAddr(off)
        currentProgram.getSymbolTable().createLabel(addr, name, SourceType.USER_DEFINED)
        
        tgt = safe_word(off)
        if tgt and tgt not in (0xFFFF, 0x0000):
            currentProgram.getSymbolTable().createLabel(toAddr(tgt), "ISR_" + name, SourceType.USER_DEFINED)
        
        off -= 2


def cleanup_leftover_blocks():
    m = mem()
    for blk in list(m.getBlocks()):
        name = blk.getName()
        # Detect leftover automatically created split blocks
        if ".split" in name or name.upper().startswith("FLASH"):
            try:
                blk.setName("UNMAPPED_FLASH")
                blk.setPermissions(True, False, True)  # RX only
                blk.setComment("Firmware bytes not mapped to known MSP430F5438 region")
                print("[D430] Renamed leftover block -> UNMAPPED_FLASH")
            except:
                pass

def main():
    print("=== Dirty430: MSP430F5438 Memory Map Splitter ===")

    for name, start, end, comment in REGIONS:
        split_block(start, end, name, comment)

    cleanup_leftover_blocks()

    sp = safe_word(RESET_SP)
    if sp:
        set_sp(sp)

    pc = safe_word(RESET_PC)
    if pc:
        set_entry_point(pc)

    label_vectors()

    print("[D430] Done. Re-run analysis.")

if __name__ == "__main__":
    main()