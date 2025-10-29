# DirtyStrings.py
# Scan for strings in raw MSP430 firmware and adds string labels + xrefs.

#@author J. DeFrancesco
#@category MSP430 Strings


from ghidra.program.model.data import StringDataType, DataUtilities
from ghidra.program.model.symbol import SourceType
import string

memory  = currentProgram.getMemory()
listing = currentProgram.getListing()
symtab  = currentProgram.getSymbolTable()

def is_printable_ascii(b):
    """Return True if a byte is printable ASCII or space."""
    return 32 <= b < 127

def read_bytes(addr, count):
    """Safely read bytes from memory."""
    try:
        bb = bytearray(count)
        memory.getBytes(addr, bb)
        return bb
    except:
        return None

def create_string_at(addr, length, label_name=None):
    """
    Safely create an ASCII string at addr if region is free.
    Clears conflicting data when safe, skips code.
    """
    dt = StringDataType()
    existing = listing.getDataAt(addr)
    if existing:
        # Already something defined here, skip
        print("Skip 0x%s (already data: %s)" % (addr, existing))
        return None
    try:
        DataUtilities.createData(
            currentProgram, addr, dt, length, False,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA
        )
        if label_name:
            symtab.createLabel(addr, label_name, SourceType.USER_DEFINED)
        print("Created string at %s (%d bytes)" % (addr, length))
        return addr
    except Exception as e:
        print("Error creating string at %s: %s" % (addr, str(e)))
        return None

def scan_memory_for_strings(min_len=4):
    """
    Scan non-executable memory blocks for printable ASCII runs.
    Creates StringData entries for runs >= min_len.
    """
    total = 0
    for blk in memory.getBlocks():
        if not blk.isInitialized() or blk.isExecute():
            continue
        base = blk.getStart()
        size = blk.getSize()
        bb = read_bytes(base, size)
        if bb is None:
            continue

        run_start = None
        run_bytes = bytearray()
        for i, b in enumerate(bb):
            if is_printable_ascii(b):
                if run_start is None:
                    run_start = base.add(i)
                run_bytes.append(b)
            else:
                if run_start and len(run_bytes) >= min_len:
                    create_string_at(run_start, len(run_bytes))
                    total += 1
                run_start = None
                run_bytes = bytearray()
        if run_start and len(run_bytes) >= min_len:
            create_string_at(run_start, len(run_bytes))
            total += 1
    print("Total strings created: %d" % total)

if __name__ == "__main__":
    scan_memory_for_strings()