# -*- coding:utf-8 -*-

# Ghidra Jython script to create a memory map for MSP430F5438 firmware reversing
# - Creates RAM block at 0x1C00 (2 KiB)
# - Creates a VECTORS placeholder at the top of a 20-bit space (0xFFFF0 sized small)
# - Adds label/comment at 0x1000 and attempts to create a function there

#@author J. DeFrancesco
#@cateforty Dirty430 Mem Map

from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.util.exception import DuplicateNameException
from ghidra.util.task import ConsoleTaskMonitor


FLASH_LOAD_ADDR = 0x001000      
FLASH_END_ADDR  = 0x045C00      
RAM_START       = 0x001C00      # MSP430F5438 RAM start
RAM_SIZE        = 0x800         # 2 KiB
VECTORS_START   = 0x0FF80     
VECTORS_SIZE    = 0x20         # 32 bytes 
BOOT_ADDR       = 0x001000     

monitor = ConsoleTaskMonitor()

memory = currentProgram.getMemory()
addrFactory = currentProgram.getAddressFactory()
addrSpace = addrFactory.getDefaultAddressSpace()

def A(x):
    return addrSpace.getAddress(x)

def exists_block_at(addr):
    try:
        b = memory.getBlock(addr)
        return b is not None
    except:
        return False

println = print

flash_start = A(FLASH_LOAD_ADDR)
flash_end = A(FLASH_END_ADDR)

println("=== D430 MSP430 Memory Map Setup script ===")
println("Program: %s" % currentProgram.getName())
println("Assumed FLASH load address: 0x%X -> 0x%X" % (FLASH_LOAD_ADDR, FLASH_END_ADDR))

block_at_flash = memory.getBlock(flash_start)
if block_at_flash:
    println("Found existing memory block at 0x%X: '%s' (size: 0x%X)" % (FLASH_LOAD_ADDR, block_at_flash.getName(), block_at_flash.getSize()))
    # FLASH
    try:
        block_at_flash.setName("FLASH")
        block_at_flash.setRead(True)
        block_at_flash.setExecute(True)
        block_at_flash.setWrite(False)
        println("Renamed existing block to 'FLASH' and set perms R-X.")
    except Exception as e:
        println("Warning: unable to rename or set perms for existing flash block: %s" % e)
else:
    println("No initialized block found at 0x%X. If you haven't loaded the raw FLASH bytes starting at 0x1000, load the binary with base 0x1000 first." % FLASH_LOAD_ADDR)
    #
    println("NOTE: This script will only create uninitialized RAM and VECTORS placeholders. If you want an initialized FLASH block, import the binary as 'Raw Binary' with base address 0x1000.")


ram_addr = A(RAM_START)
println("\n--- Creating RAM block ---")
if exists_block_at(ram_addr):
    b = memory.getBlock(ram_addr)
    println("RAM block already exists at 0x%X named '%s' (size 0x%X)" % (RAM_START, b.getName(), b.getSize()))
else:
    try:
        # create uninitialized RAM block
        memory.createUninitializedBlock("RAM", ram_addr, RAM_SIZE, False)
        b = memory.getBlock(ram_addr)
        b.setRead(True)
        b.setWrite(True)
        b.setExecute(False)
        println("Created RAM block at 0x%X length 0x%X (RW-)." % (RAM_START, RAM_SIZE))
    except Exception as e:
        println("Failed to create RAM block: %s" % e)

# Vectors
vectors_addr = A(VECTORS_START)
println("\n--- Creating VECTORS placeholder block ---")
if exists_block_at(vectors_addr):
    b = memory.getBlock(vectors_addr)
    println("Block already exists at 0x%X: '%s' (size: 0x%X)" % (VECTORS_START, b.getName(), b.getSize()))
else:
    try:
        memory.createUninitializedBlock("VECTORS", vectors_addr, VECTORS_SIZE, False)
        vb = memory.getBlock(vectors_addr)
        vb.setRead(True)
        vb.setWrite(True)
        vb.setExecute(False)
        println("Created VECTORS placeholder at 0x%X length 0x%X." % (VECTORS_START, VECTORS_SIZE))
        println("Adjust VECTORS_START in the script if you know the correct top-of-flash address for your device's vector table.")
    except Exception as e:
        println("Failed to create VECTORS block: %s" % e)

#  BSL
println("\n--- Label and function at 0x%X ---" % BOOT_ADDR)
boot_addr = A(BOOT_ADDR)
listing = currentProgram.getListing()
symTab = currentProgram.getSymbolTable()
funcMgr = currentProgram.getFunctionManager()


try:
    # createLabel takes Address, name, SourceType
    sym = symTab.createLabel(boot_addr, "_bootloader", SourceType.USER_DEFINED)
    println("Created label '_bootloader' at 0x%X" % BOOT_ADDR)
except Exception as e:
    println("Label creation: %s" % e)
    # try to find existing symbol
    s = symTab.getSymbolAt(boot_addr)
    if s:
        println("Existing symbol at 0x%X: %s" % (BOOT_ADDR, s.getName()))

# Add a plate comment
try:
    listing.setComment(boot_addr, CodeUnit.PLATE_COMMENT, "Bootloader entry (assumed). Loaded at 0x%X" % BOOT_ADDR)
    println("Added plate comment at 0x%X" % BOOT_ADDR)
except Exception as e:
    println("Failed to set comment: %s" % e)

# Try to create a function at the boot address if none exists
try:
    existing_func = funcMgr.getFunctionAt(boot_addr)
    if existing_func:
        println("Function already exists at 0x%X: %s" % (BOOT_ADDR, existing_func.getName()))
    else:
        # createFunction(name, entryPoint, body, SourceType)
        new_func = funcMgr.createFunction("_bootloader", boot_addr, None, SourceType.USER_DEFINED)
        if new_func:
            println("Created function '_bootloader' at 0x%X" % BOOT_ADDR)
        else:
            println("Failed to create function at 0x%X (createFunction returned None)" % BOOT_ADDR)
except Exception as e:
    println("Function creation error: %s" % e)

println("\n=== Done ===")
