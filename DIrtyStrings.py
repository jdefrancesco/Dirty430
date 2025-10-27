# DirtyStrings.py
# Scan for strings in raw MSP430 firmware and adds string labels + xrefs.

#@author J. DeFrancesco
#@category MSP430 Strings

from ghidra.program.model.data import DataUtilities, StringDataInstance, DataTypeConflictHandler
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit

MIN_STR_LEN = 4  # Minimum characters to qualify as a string

def is_printable_ascii(byte_val):
    """
    Check if a byte is a printable ASCII character.
    """
    return 0x20 <= byte_val <= 0x7E


def create_string_at(addr, length):
    """
    Convert raw bytes at addr into a Ghidra ASCII string data type and apply a label.
    """
    str_type = StringDataInstance.getStringDataType()

    DataUtilities.createData(
        currentProgram,
        addr,
        str_type,
        length + 1,  
        False,
        DataTypeConflictHandler.DEFAULT_HANDLER
    )

    # If no label exists, create one
    symbol = getSymbolAt(addr)
    if symbol is None:
        raw_name = get_string_preview(addr, length)
        label = "str_" + raw_name
        createLabel(addr, label, False)

    return getSymbolAt(addr).getName()


def get_string_preview(addr, length):
    """Return a small label-friendly name from string content (alphanumeric only)."""
    name = ""
    for i in range(length):
        c = chr(getByte(addr.add(i)))
        if c.isalnum():
            name += c
    if len(name) == 0:
        name = "unk"
    return name[:12]


def add_xrefs(addr):
    """Finds and logs cross-references to the string at this address."""
    refs = getReferencesTo(addr)
    for ref in refs:
        from_addr = ref.getFromAddress()
        func = getFunctionContaining(from_addr)
        if func:
            print("    XREF from {} in function {}".format(from_addr, func.getName()))
        else:
            print("    XREF from {}".format(from_addr))


def scan_memory_for_strings():
    """
    Scans all memory blocks for ASCII strings, creates string data,
    labels them, and reports xrefs.
    """
    memory = currentProgram.getMemory()
    print("[*] Scanning memory for strings + xrefs...")

    for block in memory.getBlocks():
        start = block.getStart()
        end   = block.getEnd()
        addr  = start

        while addr <= end:
            run_start = addr
            run_bytes = []

            # Gather bytes while printable
            while addr <= end and is_printable_ascii(getByte(addr)):
                run_bytes.append(getByte(addr))
                addr = addr.add(1)

            # If we found a valid string, define it & process xrefs
            if len(run_bytes) >= MIN_STR_LEN:
                label = create_string_at(run_start, len(run_bytes))
                print("[+] String at {} -> '{}'".format(run_start, label))
                add_xrefs(run_start)

            addr = addr.add(1)

    print("[*] String scan completed.")


# Entrypoint for Ghidra
if __name__ == "__main__" or str(__name__).startswith("__main__"):
    scan_memory_for_strings()
