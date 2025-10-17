# DirtyMemBlockRename.py 
# MSP430F5438 Memory Block Renamer
# Automatically renames memory blocks based on known MSP430F5438 address ranges.
# Safe to re-run — will only rename matching ranges.
#

#@author J. DeFrancesco
#@category Memory
from ghidra.program.model.mem import MemoryBlock

# MSP430F5438 memory map (from TI datasheet)
REGIONS = [
    ("PERIPHERALS",   0x00000, 0x00FFF, "SFR + peripherals (4 KB)"),
    ("BSL_ROM",       0x01000, 0x017FF, "Bootloader ROM (2 KB)"),
    ("INFO_FLASH_D",  0x01800, 0x0187F, "Info Flash D (128 B)"),
    ("INFO_FLASH_C",  0x01880, 0x018FF, "Info Flash C (128 B)"),
    ("INFO_FLASH_B",  0x01900, 0x0197F, "Info Flash B (128 B)"),
    ("INFO_FLASH_A",  0x01980, 0x019FF, "Info Flash A (128 B)"),
    ("SRAM",          0x01C00, 0x05BFF, "Main RAM (16 KB)"),
    ("MAIN_FLASH_LO", 0x05C00, 0x0FF7F, "Main Flash lower window"),
    ("INT_VECTORS",   0x0FF80, 0x0FFFF, "Interrupt vectors"),
    ("MAIN_FLASH_B1", 0x10000, 0x1FFFF, "Main Flash Bank 1"),
    ("MAIN_FLASH_B2", 0x20000, 0x2FFFF, "Main Flash Bank 2"),
    ("MAIN_FLASH_B3", 0x30000, 0x3FFFF, "Main Flash Bank 3"),
    ("MAIN_FLASH_B4", 0x40000, 0x45BFF, "Main Flash Bank 4 partial"),
]

def toAddr(x):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x)

def rename_block_for_region(mem, name, lo, hi, desc):
    """Find a block covering [lo,hi] and rename it."""

    blk = mem.getBlock(toAddr(lo))
    if not blk:
        print("[!] No block starting at 0x%05X; skipping %s" % (lo, name))
        return
    # Ensure it overlaps or fully matches
    blk_lo = blk.getStart().getOffset()
    blk_hi = blk.getEnd().getOffset()
    if not (blk_lo <= hi and blk_hi >= lo):
        print("[!] Block %s (0x%05X–0x%05X) doesn’t overlap %s range 0x%05X–0x%05X" %
              (blk.getName(), blk_lo, blk_hi, name, lo, hi))
        return
    old_name = blk.getName()
    if old_name == name:
        print("[=] %-18s already named correctly" % name)
        return
    try:
        blk.setName(name)
        blk.setComment(desc)
        print("[+] Renamed %-18s @ 0x%05X–0x%05X (was %s)" % (name, lo, hi, old_name))
    except Exception as e:
        print("[!] Could not rename block %s → %s: %s" % (old_name, name, e))

def main():
    print("=== D430 Memory Block Rename ===")
    mem = currentProgram.getMemory()
    for (name, lo, hi, desc) in REGIONS:
        rename_block_for_region(mem, name, lo, hi, desc)
    print("=== Done! Check Memory Map window ===")

if __name__ == "__main__":
    main()
