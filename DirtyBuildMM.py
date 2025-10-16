# -*- coding: utf-8 -*-
# MSP430F5438A Memory Map Setup Script
# Creates MSP430F5438A memory map inside Ghidra

#@author J. DeFrancesco
#@category Memory


from ghidra.program.model.address import Address
from ghidra.program.model.data import WordDataType
from ghidra.program.model.mem import MemoryConflictException

def addr(hex_str):
    return currentProgram.getAddressFactory().getAddress(hex_str)

def block_overlaps(start, end):
    mem = currentProgram.getMemory()
    for b in mem.getBlocks():
        if not (end.compareTo(b.getStart()) < 0 or start.compareTo(b.getEnd()) > 0):
            return True
    return False

# def make_block(name, start, end, perms="r", space=None):
#     mem = currentProgram.getMemory()
#     size = end.subtract(start) + 1
#     af = currentProgram.getAddressFactory()
    
#     # accept either Address or hex string
#     if isinstance(start, basestring):
#         start_addr = af.getAddress(start) if space is None else af.getAddress(space + ":" + start)
#     else:
#         start_addr = start

#     if isinstance(end, basestring):
#         end_addr = af.getAddress(end) if space is None else af.getAddress(space + ":" + end)
#     else:
#         end_addr = end


#     if block_overlaps(start, end):
#         print("[=] Skipping overlap region {0}: {1}-{2}".format(name, start, end))
#         return None

#     try:
#         block = mem.createUninitializedBlock(name, start, size, False)
#         read = 'r' in perms
#         write = 'w' in perms
#         execute = 'x' in perms
#         block.setPermissions(read, write, execute)
#         print("[+] Created {0:<12} {1}-{2} ({3} bytes) perms={4}".format(name, start, end, size, perms))
#         return block
#     except MemoryConflictException:
#         print("[=] Overlap detected, skipping {0}".format(name))
#     except Exception as e:
#         print("[!] Error creating {0}: {1}".format(name, str(e)))
#     return None


def make_block(name, start, end, perms="r", space=None):
    mem = currentProgram.getMemory()
    af  = currentProgram.getAddressFactory()

    # Accept either strings or Address objects
    if isinstance(start, basestring):
        start_addr = af.getAddress(start) if space is None else af.getAddress(space + ":" + start)
    else:
        start_addr = start

    if isinstance(end, basestring):
        end_addr = af.getAddress(end) if space is None else af.getAddress(space + ":" + end)
    else:
        end_addr = end

    if block_overlaps(start_addr, end_addr):
        print("[=] Skipping overlap region {0}: {1}-{2}".format(name, start_addr, end_addr))
        return None

    try:
        size = end_addr.subtract(start_addr) + 1
        block = mem.createUninitializedBlock(name, start_addr, size, False)
        block.setPermissions('r' in perms, 'w' in perms, 'x' in perms)
        print("[+] Created {0:<12} {1}-{2} perms={3}".format(name, start_addr, end_addr, perms))
        return block
    except Exception as e:
        print("[!] Error creating {0}: {1}".format(name, str(e)))
        return None
    
def create_map():
    # Peripheral / system regions
    make_block("PERIPH", addr("0x0000"), addr("0x0FFF"), "rw")
    make_block("BSL", addr("0x1000"), addr("0x17FF"), "rx")
    make_block("INFO_FLASH", addr("0x1800"), addr("0x19FF"), "rw")
    make_block("RAM", addr("0x1C00"), addr("0x5BFF"), "rw")
    # Alias block for legacy 16-bit wraparound addresses (prevents access exceptions)
    make_block("RAM_ALIAS", addr("0xFF00"), addr("0xFFFF"), "rw", space="RAM")

    # Main Flash (non-banked portion)
    make_block("FLASH_MAIN", addr("0x05C00"), addr("0x3DFFF"), "rx")

    # Top Banks
    make_block("BANK_D", addr("0x3E000"), addr("0x3FFFF"), "rx")
    make_block("BANK_C", addr("0x40000"), addr("0x41FFF"), "rx")
    make_block("BANK_B", addr("0x42000"), addr("0x43FFF"), "rx")
    make_block("BANK_A", addr("0x44000"), addr("0x45BFF"), "rx")

    print("[+] Memory map creation complete.\n")

def label_reset_vector():
    listing = currentProgram.getListing()
    try:
        reset_addr = addr("0x45BFE")  # end of Bank A
        createLabel(reset_addr, "RESET_VECTOR", True)
        listing.createData(reset_addr, WordDataType.dataType)
        print("[+] Labeled RESET_VECTOR at " + str(reset_addr))
    except Exception as e:
        print("[!] Could not label reset vector: " + str(e))

def main():
    print("=== MSP430F5438A Memory Map Setup (Banks A-D) ===")
    create_map()
    print("=== Done. Run Auto-Analysis (Ctrl-Shift-A) next. ===")

if __name__ == "__main__":
    main()