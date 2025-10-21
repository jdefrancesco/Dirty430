# -*- coding: utf-8 -*-
# Dirty430.py - Ghidra script to fix up MSP430F5438 binaries. It first labels all memory
# mapped registers and creates functions at interrupt vectors if need be.


#@author J. DeFrancesco
#@category MSP430

from ghidra.util import Msg # pyright: ignore[reportMissingModuleSource]
from ghidra.program.model.symbol import SourceType # pyright: ignore[reportMissingModuleSource]
from ghidra.program.model.data import ByteDataType, WordDataType # pyright: ignore[reportMissingModuleSource]
from ghidra.program.model.address import AddressOutOfBoundsException # pyright: ignore[reportMissingModuleSource]

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnit

try:
    from ghidra.program.flatapi import FlatProgramAPI
except Exception:
    FlatProgramAPI = None

from ghidra.program.model.data import (
    DataUtilities, Undefined1DataType, Undefined2DataType,
    Undefined4DataType, ByteDataType, WordDataType, DWordDataType
)

from java.math import BigInteger
from ghidra.program.model.lang import RegisterValue
from ghidra.program.model.symbol import SourceType

# Register blocks for the MSP430F5438, from the datasheet.
MSP430F5438_REG_BLOCKS = {
    0x0100: {"name": "SFR", "regs": [                 # Table 6-12
        ("SFRIE1",  0x00), ("SFRIFG1", 0x02), ("SFRRPCR", 0x04),
    ]},
    0x0120: {"name": "PMM", "regs": [                 # Table 6-13
        ("PMMCTL0", 0x00), ("PMMCTL1", 0x02),
        ("SVSMHCTL", 0x04), ("SVSMLCTL", 0x06),
        ("PMMIFG",  0x0C), ("PMMIE",   0x0E),
    ]},
    0x0140: {"name": "FLASH", "regs": [               # Table 6-14
        ("FCTL1", 0x00), ("FCTL3", 0x04), ("FCTL4", 0x06),
    ]},
    0x0150: {"name": "CRC16", "regs": [               # Table 6-15
        ("CRC16DI",    0x00), ("CRC16INIRES", 0x04),
    ]},
    0x0158: {"name": "RAMCTL", "regs": [              # Table 6-16
        ("RCCTL0", 0x00),
    ]},
    0x015C: {"name": "WDT", "regs": [                 # Table 6-17
        ("WDTCTL", 0x00),
    ]},
    0x0160: {"name": "UCS", "regs": [                 # Table 6-18
        ("UCSCTL0", 0x00), ("UCSCTL1", 0x02), ("UCSCTL2", 0x04),
        ("UCSCTL3", 0x06), ("UCSCTL4", 0x08), ("UCSCTL5", 0x0A),
        ("UCSCTL6", 0x0C), ("UCSCTL7", 0x0E), ("UCSCTL8", 0x10),
    ]},
    0x0180: {"name": "SYS", "regs": [                 # Table 6-19
        ("SYSCTL", 0x00), ("SYSBSLC", 0x02),
        ("SYSJMBC", 0x06), ("SYSJMBI0", 0x08), ("SYSJMBI1", 0x0A),
        ("SYSJMBO0", 0x0C), ("SYSJMBO1", 0x0E),
        ("SYSBERRIV", 0x18), ("SYSUNIV", 0x1A),
        ("SYSSNIV", 0x1C), ("SYSRSTIV", 0x1E),
    ]},

    # GPIO blocks (Tables 6-20..6-26)
    0x0200: {"name": "P1P2", "regs": [
        ("P1IN",0x00),("P1OUT",0x02),("P1DIR",0x04),("P1REN",0x06),
        ("P1DS",0x08),("P1SEL",0x0A),("P1IV",0x0E),("P1IES",0x18),
        ("P1IE",0x1A),("P1IFG",0x1C),
        ("P2IN",0x01),("P2OUT",0x03),("P2DIR",0x05),("P2REN",0x07),
        ("P2DS",0x09),("P2SEL",0x0B),("P2IV",0x1E),("P2IES",0x19),
        ("P2IE",0x1B),("P2IFG",0x1D),
    ]},
    0x0220: {"name": "P3P4", "regs": [
        ("P3IN",0x00),("P3OUT",0x02),("P3DIR",0x04),("P3REN",0x06),
        ("P3DS",0x08),("P3SEL",0x0A),
        ("P4IN",0x01),("P4OUT",0x03),("P4DIR",0x05),("P4REN",0x07),
        ("P4DS",0x09),("P4SEL",0x0B),
    ]},
    0x0240: {"name": "P5P6", "regs": [
        ("P5IN",0x00),("P5OUT",0x02),("P5DIR",0x04),("P5REN",0x06),
        ("P5DS",0x08),("P5SEL",0x0A),
        ("P6IN",0x01),("P6OUT",0x03),("P6DIR",0x05),("P6REN",0x07),
        ("P6DS",0x09),("P6SEL",0x0B),
    ]},
    0x0260: {"name": "P7P8", "regs": [
        ("P7IN",0x00),("P7OUT",0x02),("P7DIR",0x04),("P7REN",0x06),
        ("P7DS",0x08),("P7SEL",0x0A),
        ("P8IN",0x01),("P8OUT",0x03),("P8DIR",0x05),("P8REN",0x07),
        ("P8DS",0x09),("P8SEL",0x0B),
    ]},
    0x0280: {"name": "P9P10", "regs": [
        ("P9IN",0x00),("P9OUT",0x02),("P9DIR",0x04),("P9REN",0x06),
        ("P9DS",0x08),("P9SEL",0x0A),
        ("P10IN",0x01),("P10OUT",0x03),("P10DIR",0x05),("P10REN",0x07),
        ("P10DS",0x09),("P10SEL",0x0B),
    ]},
    0x02A0: {"name": "P11", "regs": [
        ("P11IN",0x00),("P11OUT",0x02),("P11DIR",0x04),("P11REN",0x06),
        ("P11DS",0x08),("P11SEL",0x0A),
    ]},
    0x0320: {"name": "PJ", "regs": [                 # Port J
        ("PJIN",0x00),("PJOUT",0x02),("PJDIR",0x04),("PJREN",0x06),
        ("PJDS",0x08),
    ]},

    # Timers (Tables 6-27..6-29)
    0x0340: {"name": "TA0", "regs": [
        ("TA0CTL",0x00),
        ("TA0CCTL0",0x02),("TA0CCTL1",0x04),("TA0CCTL2",0x06),
        ("TA0CCTL3",0x08),("TA0CCTL4",0x0A),
        ("TA0R",0x10),
        ("TA0CCR0",0x12),("TA0CCR1",0x14),("TA0CCR2",0x16),
        ("TA0CCR3",0x18),("TA0CCR4",0x1A),
        ("TA0EX0",0x20),("TA0IV",0x2E),
    ]},
    0x0380: {"name": "TA1", "regs": [
        ("TA1CTL",0x00),
        ("TA1CCTL0",0x02),("TA1CCTL1",0x04),("TA1CCTL2",0x06),
        ("TA1R",0x10),("TA1CCR0",0x12),("TA1CCR1",0x14),("TA1CCR2",0x16),
        ("TA1EX0",0x20),("TA1IV",0x2E),
    ]},
    0x03C0: {"name": "TB0", "regs": [
        ("TB0CTL",0x00),
        ("TB0CCTL0",0x02),("TB0CCTL1",0x04),("TB0CCTL2",0x06),
        ("TB0CCTL3",0x08),("TB0CCTL4",0x0A),("TB0CCTL5",0x0C),("TB0CCTL6",0x0E),
        ("TB0R",0x10),("TB0CCR0",0x12),("TB0CCR1",0x14),("TB0CCR2",0x16),
        ("TB0CCR3",0x18),("TB0CCR4",0x1A),("TB0CCR5",0x1C),("TB0CCR6",0x1E),
        ("TB0EX0",0x20),("TB0IV",0x2E),
    ]},

    # MPY32 (Table 6-31)
    0x04C0: {"name": "MPY32", "regs": [
        ("MPY",0x00),("MPYS",0x02),("MAC",0x04),("MACS",0x06),
        ("OP2",0x08),
        ("RESLO",0x0A),("RESHI",0x0C),("SUMEXT",0x0E),
        ("MPY32L",0x10),("MPY32H",0x12),("MPYS32L",0x14),("MPYS32H",0x16),
        ("MAC32L",0x18),("MAC32H",0x1A),("MACS32L",0x1C),("MACS32H",0x1E),
        ("OP2L",0x20),("OP2H",0x22),("RES0",0x24),("RES1",0x26),
        ("RES2",0x28),("RES3",0x2A),("MPY32CTL0",0x2C),
    ]},

    # DMA (Table 6-32): general + channels 0..2
    0x0500: {"name": "DMA", "regs": [
        ("DMACTL0",0x00),("DMACTL1",0x02),("DMACTL2",0x04),
        ("DMACTL3",0x06),("DMACTL4",0x08),("DMAIV",0x0E),
    ]},
    0x0510: {"name": "DMA0", "regs": [
        ("DMA0CTL",0x00),("DMA0SAL",0x02),("DMA0SAH",0x04),
        ("DMA0DAL",0x06),("DMA0DAH",0x08),("DMA0SZ",0x0A),
    ]},
    0x0520: {"name": "DMA1", "regs": [
        ("DMA1CTL",0x00),("DMA1SAL",0x02),("DMA1SAH",0x04),
        ("DMA1DAL",0x06),("DMA1DAH",0x08),("DMA1SZ",0x0A),
    ]},
    0x0530: {"name": "DMA2", "regs": [
        ("DMA2CTL",0x00),("DMA2SAL",0x02),("DMA2SAH",0x04),
        ("DMA2DAL",0x06),("DMA2DAH",0x08),("DMA2SZ",0x0A),
    ]},

    # USCI modules (Tables 6-33..6-40)
    0x05C0: {"name": "UCA0", "regs": [
        ("UCA0CTL1",0x00),("UCA0CTL0",0x01),("UCA0BR0",0x06),("UCA0BR1",0x07),
        ("UCA0MCTL",0x08),("UCA0STAT",0x0A),("UCA0RXBUF",0x0C),("UCA0TXBUF",0x0E),
        ("UCA0ABCTL",0x10),("UCA0IRTCTL",0x12),("UCA0IRRCTL",0x13),
        ("UCA0IE",0x1C),("UCA0IFG",0x1D),("UCA0IV",0x1E),
    ]},
    0x05E0: {"name": "UCB0", "regs": [
        ("UCB0CTL1",0x00),("UCB0CTL0",0x01),("UCB0BR0",0x06),("UCB0BR1",0x07),
        ("UCB0STAT",0x0A),("UCB0RXBUF",0x0C),("UCB0TXBUF",0x0E),
        ("UCB0I2COA",0x10),("UCB0I2CSA",0x12),
        ("UCB0IE",0x1C),("UCB0IFG",0x1D),("UCB0IV",0x1E),
    ]},
    0x0600: {"name": "UCA1", "regs": [
        ("UCA1CTL1",0x00),("UCA1CTL0",0x01),("UCA1BR0",0x06),("UCA1BR1",0x07),
        ("UCA1MCTL",0x08),("UCA1STAT",0x0A),("UCA1RXBUF",0x0C),("UCA1TXBUF",0x0E),
        ("UCA1ABCTL",0x10),("UCA1IRTCTL",0x12),("UCA1IRRCTL",0x13),
        ("UCA1IE",0x1C),("UCA1IFG",0x1D),("UCA1IV",0x1E),
    ]},
    0x0620: {"name": "UCB1", "regs": [
        ("UCB1CTL1",0x00),("UCB1CTL0",0x01),("UCB1BR0",0x06),("UCB1BR1",0x07),
        ("UCB1STAT",0x0A),("UCB1RXBUF",0x0C),("UCB1TXBUF",0x0E),
        ("UCB1I2COA",0x10),("UCB1I2CSA",0x12),
        ("UCB1IE",0x1C),("UCB1IFG",0x1D),("UCB1IV",0x1E),
    ]},
    0x0640: {"name": "UCA2", "regs": [
        ("UCA2CTL1",0x00),("UCA2CTL0",0x01),("UCA2BR0",0x06),("UCA2BR1",0x07),
        ("UCA2MCTL",0x08),("UCA2STAT",0x0A),("UCA2RXBUF",0x0C),("UCA2TXBUF",0x0E),
        ("UCA2ABCTL",0x10),("UCA2IRTCTL",0x12),("UCA2IRRCTL",0x13),
        ("UCA2IE",0x1C),("UCA2IFG",0x1D),("UCA2IV",0x1E),
    ]},
    0x0660: {"name": "UCB2", "regs": [
        ("UCB2CTL1",0x00),("UCB2CTL0",0x01),("UCB2BR0",0x06),("UCB2BR1",0x07),
        ("UCB2STAT",0x0A),("UCB2RXBUF",0x0C),("UCB2TXBUF",0x0E),
        ("UCB2I2COA",0x10),("UCB2I2CSA",0x12),
        ("UCB2IE",0x1C),("UCB2IFG",0x1D),("UCB2IV",0x1E),
    ]},
    0x0680: {"name": "UCA3", "regs": [
        ("UCA3CTL1",0x00),("UCA3CTL0",0x01),("UCA3BR0",0x06),("UCA3BR1",0x07),
        ("UCA3MCTL",0x08),("UCA3STAT",0x0A),("UCA3RXBUF",0x0C),("UCA3TXBUF",0x0E),
        ("UCA3ABCTL",0x10),("UCA3IRTCTL",0x12),("UCA3IRRCTL",0x13),
        ("UCA3IE",0x1C),("UCA3IFG",0x1D),("UCA3IV",0x1E),
    ]},
    0x06A0: {"name": "UCB3", "regs": [
        ("UCB3CTL1",0x00),("UCB3CTL0",0x01),("UCB3BR0",0x06),("UCB3BR1",0x07),
        ("UCB3STAT",0x0A),("UCB3RXBUF",0x0C),("UCB3TXBUF",0x0E),
        ("UCB3I2COA",0x10),("UCB3I2CSA",0x12),
        ("UCB3IE",0x1C),("UCB3IFG",0x1D),("UCB3IV",0x1E),
    ]},

    # ADC12_A (Table 6-41)
    0x0700: {"name": "ADC12_A", "regs": [
        ("ADC12CTL0",0x00),("ADC12CTL1",0x02),("ADC12CTL2",0x04),
        ("ADC12IFG",0x0A), ("ADC12IE",0x0C), ("ADC12IV",0x0E),
        # MCTL0..15 and MEM0..15
        # control
        ("ADC12MCTL0",0x10),("ADC12MCTL1",0x11),("ADC12MCTL2",0x12),("ADC12MCTL3",0x13),
        ("ADC12MCTL4",0x14),("ADC12MCTL5",0x15),("ADC12MCTL6",0x16),("ADC12MCTL7",0x17),
        ("ADC12MCTL8",0x18),("ADC12MCTL9",0x19),("ADC12MCTL10",0x1A),("ADC12MCTL11",0x1B),
        ("ADC12MCTL12",0x1C),("ADC12MCTL13",0x1D),("ADC12MCTL14",0x1E),("ADC12MCTL15",0x1F),
        # data
        ("ADC12MEM0",0x20),("ADC12MEM1",0x22),("ADC12MEM2",0x24),("ADC12MEM3",0x26),
        ("ADC12MEM4",0x28),("ADC12MEM5",0x2A),("ADC12MEM6",0x2C),("ADC12MEM7",0x2E),
        ("ADC12MEM8",0x30),("ADC12MEM9",0x32),("ADC12MEM10",0x34),("ADC12MEM11",0x36),
        ("ADC12MEM12",0x38),("ADC12MEM13",0x3A),("ADC12MEM14",0x3C),("ADC12MEM15",0x3E),
    ]},
}

# Selected high-signal regs we see a lot in firmware. 
REG_BITFIELDS = {
    # Watchdog Timer Control
    'WDTCTL': {
        'WDTPW':   0x5A00,
        'WDTHOLD': 0x0080,
        'WDTSSEL0':0x0020,
        'WDTSSEL1':0x0040,
        'WDTTMSEL':0x0010,
        'WDTCNTCL':0x0008,
        'WDTIS0':  0x0001,
        'WDTIS1':  0x0002,
        'WDTIS2':  0x0004,
    },

    # Unified Clock System Control 4
    'UCSCTL4': {
        'SELA0': 0x0100,
        'SELA1': 0x0200,
        'SELA2': 0x0400,
        'SELS0': 0x0020,
        'SELS1': 0x0040,
        'SELM0': 0x0001,
        'SELM1': 0x0002,
        'SELM2': 0x0004,
    },

    # Timer_A/Timer_B Control (applies to TA0CTL, TA1CTL, TB0CTL etc.)
    'TAxCTL': {
        'TASSEL0': 0x0100,
        'TASSEL1': 0x0200,
        'ID0':     0x0040,
        'ID1':     0x0080,
        'MC0':     0x0010,
        'MC1':     0x0020,
        'TACLR':   0x0004,
        'TAIE':    0x0002,
        'TAIFG':   0x0001,
    },

    # ADC12_A Control 0
    'ADC12CTL0': {
        'ADC12SHT0_MASK': 0x0F00,  # sample/hold 0 field
        'ADC12SHT1_MASK': 0xF000,  # sample/hold 1 field
        'ADC12MSC':       0x0080,
        'ADC12REF2_5V':   0x0040,
        'ADC12REFON':     0x0020,
        'ADC12ON':        0x0010,
        'ADC12OVIE':      0x0008,
        'ADC12TOVIE':     0x0004,
        'ADC12ENC':       0x0002,
        'ADC12SC':        0x0001,
    },

    # Special Function Register Interrupt Enable 1
    'SFRIE1': {
        'JMBOUTIE': 0x0080,
        'JMBINIE':  0x0040,
        'ACCVIE':   0x0020,
        'NMIIE':    0x0010,
        'VMAIE':    0x0008,
        'OFIE':     0x0002,
        'WDTIE':    0x0001,
    },
}

# Some registers share the same bit layout as TAxCTL; map specific names to that template
_BITFIELD_ALIASES = {
    'TA0CTL': 'TAxCTL',
    'TA1CTL': 'TAxCTL',
    'TB0CTL': 'TAxCTL',
}



def addr_int(a):
    """Return integer offset for either an int/long or a Ghidra Address-like object."""

    if a is None:
        return 0

    # Ghidra Address objects have getOffset / getUnsignedOffset
    if hasattr(a, 'getOffset'):
        try:
            return int(a.getOffset())
        except Exception:
            pass
    try:
        return int(a)
    except Exception:
        return 0


def fmt_addr(a):
    """Format an address or int as 0xXXXXXXXX cause it annoys me."""

    return "0x%X" % addr_int(a)


def to_addr(addr):
    """Convert an integer to an Address object."""

    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr)


def mem_has(a_addr):
    """Check if memory contains the given address."""

    try:
        return currentProgram.getMemory().contains(to_addr(a_addr))
    except AddressOutOfBoundsException as e:
        Msg.error(None, "[!] Address out of bounds: %s" % e )
        return False


def apply_bitfield_comments():
    """Add EOL comments with bitfield names for known registers.

    Works for entries from both EMBEDDED_REGS and MSP430F5438_REG_BLOCKS.
    Returns count of annotations applied.
    """

    listing = currentProgram.getListing()
    applied = 0

    def _annotate(addr_int, reg_name):
        try:
            # resolve alias
            bits = REG_BITFIELDS.get(reg_name)
            if bits is None:
                alias = _BITFIELD_ALIASES.get(reg_name)
                if alias:
                    bits = REG_BITFIELDS.get(alias)
            if bits is None:
                return 0
            a = to_addr(addr_int)
            cu = listing.getCodeUnitAt(a)
            if cu is None:
                # create a byte/word so we have a codeunit to annotate
                width = 2 if ('_MASK' in ''.join(bits.keys()) or any(v > 0xFF for v in bits.values())) else 1
                make_data(addr_int, width)
                cu = listing.getCodeUnitAt(a)
            txt = _comment_text_for_bits(bits)
            cu.setComment(CodeUnit.EOL_COMMENT, txt)
            return 1
        except Exception:
            return 0

    # From the structured blocks
    for base, blk in MSP430F5438_REG_BLOCKS.items():
        regs = blk.get('regs', [])
        for (name, off) in regs:
            applied += _annotate(base + off, name)

    return applied

def make_label(addr, name):
    """Create a label at the given address with the specified name."""

    a_addr = to_addr(addr)
    Msg.info(None, "[i] Creating label %s at %s" % (name, fmt_addr(a_addr)))
    for s in gPM.getSymbolTable().getSymbols(a_addr):
        if s.getSource() == SourceType.USER_DEFINED:
            return False  # user label exists, skip

    createLabel(a_addr, name, True, SourceType.USER_DEFINED)
    return True

def install_msp430f5438_labels(program=None):
    """Create labels for MSP430F5438/5438A memory-mapped registers."""

    fpa = FlatProgramAPI(program)
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()

    created = 0
    for base, meta in MSP430F5438_REG_BLOCKS.items():
        blockname = meta["name"]
        for (rname, off) in meta["regs"]:
            addr = space.getAddress(base + off)
            label = rname
            try:
                # Create or replace existing label with the canonical name
                fpa.createLabel(addr, label, True)
                # Helpful EOL comment with block base + offset
                try:
                    cu = program.getListing().getCodeUnitAt(addr)
                    if cu is not None:
                        comment = "{} base 0x{:04X} + 0x{:02X}".format(blockname, base, off)
                        cu.setComment(CodeUnit.EOL_COMMENT, comment)
                except Exception:
                    pass
                created += 1
            except Exception:
                # Label may already exist; skip silently
                pass

    print("[D430] labeled {} MSP430F5438 registers".format(created))


def has_user_defined_symbol(addr_obj):
    """Return True if a user defined symbol exists at the address."""

    for symbol in currentProgram.getSymbolTable().getSymbols(addr_obj):
        if symbol.getSource() == SourceType.USER_DEFINED:
            return True
    return False

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
        print("[D430] Fixed undefined data types to standard types.")

def rename_dat_globals():
    symtab = currentProgram.getSymbolTable()
    for sym in symtab.getAllSymbols(True):
        name = sym.getName()
        if name.startswith("DAT_"):
            new_name = "g_" + name[4:].lower()
            try:
                symtab.renameSymbol(sym, new_name, None)
                print("[D430] Renamed %s -> %s" % (name, new_name))
            except:
                pass


# Memory regions for MSP430F5438
REGIONS = [
    ("PERIPHERALS",   0x00000, 0x00FFF, "SFR + peripherals"),
    ("BSL_ROM",       0x01000, 0x017FF, "Bootloader ROM"),
    ("INFO_FLASH_D",  0x01800, 0x0187F, "Info Flash D"),
    ("INFO_FLASH_C",  0x01880, 0x018FF, "Info Flash C"),
    ("INFO_FLASH_B",  0x01900, 0x0197F, "Info Flash B"),
    ("INFO_FLASH_A",  0x01980, 0x019FF, "Info Flash A"),
    ("TLV",           0x01A00, 0x01AFF, "TLV Info"),
    ("Factory Boot",  0x01B00, 0x01BFF, "Factory Boot code"),
    ("SRAM",          0x01C00, 0x05BFF, "Main RAM"),
    ("MAIN_FLASH_LO", 0x05C00, 0x0FF7F, "Main Flash lower"),
    ("INT_VECTORS",   0x0FF80, 0x0FFFF, "Interrupt vectors"),
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

def split_mem_block():
    print("[D430] Fixing MSP430F5438 Memory Map ")

    for name, start, end, comment in REGIONS:
        split_block(start, end, name, comment)

    cleanup_leftover_blocks()

    print("[D430] Setting Reset SP and PC ")
    sp = safe_word(RESET_SP)
    if sp:
        set_sp(sp)

    pc = safe_word(RESET_PC)
    if pc:
        set_entry_point(pc)

    print("[D430]: Labeling Interrupt Vectors ")
    label_vectors()

    print("[D430] Memory Map fix complete.\n")

def clean_function(func):
    func.setCustomVariableStorage(True)
    func.setStackPurgeSize(0)
    func.setReturnAddressOffset(0)

    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    ifc.setOptions(ifc.getOptions())
    ifc.decompileFunction(func, 30, ConsoleTaskMonitor())

def clean_functions():
    print("[D430] Cleaning decompiler artifacts...")

    #  Replace undefined types
    fix_data_types()

    #  Rename ugly DAT_ globals
    rename_dat_globals()

    # Clean all functions
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        clean_function(func)

    print("[D430] Press Ctrl+Shift+R in decompiler to refresh view.")

def main():
    """Main function. """

    print("======= Starting Dirty430 script  =======\n\n")

    print("[D430] Fixing Memory Map.")
    split_mem_block()

    # Insert more complete set of MSP430F5438 register labels
    print("[D430] Installing MSP430F5438 register labels...")
    install_msp430f5438_labels(program=currentProgram)


    # Add bitfield comments
    print("[D430] Applying bitfield comments to known registers...")
    apply_bitfield_comments()

    print("[i] Fixing Data Types...")
    # TODO: Replace with clean_functions()?
    fix_data_types()
  
    print("======= Finished Dirty430 =======")

if __name__ == "__main__":
    main()
