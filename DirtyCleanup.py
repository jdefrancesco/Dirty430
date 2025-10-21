# -*- coding: utf-8 -*-
# DirtyCleanup.py
# MSP430F5438 Memory Block Renamer

#@author J. DeFrancesco
#@category Memory

from ghidra.program.model.data import (
    DataUtilities, Undefined1DataType, Undefined2DataType,
    Undefined4DataType, ByteDataType, WordDataType, DWordDataType
)
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def fix_data_types():
    dtm = currentProgram.getDataTypeManager()
    changed = False

    # Replace undefined1→uint8_t, undefined2→uint16_t, undefined4→uint32_t
    for dt in dtm.getAllDataTypes():
        if isinstance(dt, Undefined1DataType):
            dtm.replaceDataType(dt, ByteDataType.dataType, True)
            changed = True
        elif isinstance(dt, Undefined2DataType):
            dtm.replaceDataType(dt, WordDataType.dataType, True)
            changed = True
        elif isinstance(dt, Undefined4DataType):
            dtm.replaceDataType(dt, DWordDataType.dataType, True)
            changed = True
    if changed:
        print("[+] Replaced undefined types with fixed-width types.")

def rename_dat_globals():
    symtab = currentProgram.getSymbolTable()
    for sym in symtab.getAllSymbols(True):
        name = sym.getName()
        if name.startswith("DAT_"):
            new_name = "g_" + name[4:].lower()
            try:
                symtab.renameSymbol(sym, new_name, None)
                print(f"[+] Renamed {name} -> {new_name}")
            except:
                pass

def clean_function(func):
    func.setCustomVariableStorage(True)
    func.setStackPurgeSize(0)
    func.setReturnAddressOffset(0)

    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    ifc.setOptions(ifc.getOptions())
    ifc.decompileFunction(func, 30, ConsoleTaskMonitor())

def main():
    print("[*] Cleaning decompiler artifacts...")

    # Step 1: Replace undefined types
    fix_data_types()

    # Step 2: Rename ugly DAT_ globals
    rename_dat_globals()

    # Step 3: Clean all functions
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        clean_function(func)

    print("\n Done. Press Ctrl+Shift+R in decompiler to refresh view.")

if __name__ == "__main__":
    main()