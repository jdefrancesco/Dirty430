# -*- coding: utf-8 -*-
# Dirty430.py - Ghidra script to fix up MSP430F5438 binaries. It first labels all memory
# mapped registers and creates functions at interrupt vectors if need be.
# After that we attempt to clean the C up a bit by doing the following:

# NOTE: See DirtyDecompiler.py.
#  - MUL/DIV SimplIfications (No hardware support on msp430s)
#  - Cleanup any weird stack behavior (to some degree anyway)
#  - Bitmask macro cleanup
#  - Switch recovery
#  - Struct detection
#  - Peripheral register renaming (if mapping provided)
#  - Constant folding
#
# - Will be provided in another module during debug.

#@author J. DeFrancesco
#@category MSP430

from ghidra.util import Msg # pyright: ignore[reportMissingModuleSource]
from ghidra.program.model.symbol import SourceType # pyright: ignore[reportMissingModuleSource]
from ghidra.program.model.data import ByteDataType, WordDataType # pyright: ignore[reportMissingModuleSource]
from ghidra.program.model.address import AddressOutOfBoundsException # pyright: ignore[reportMissingModuleSource]

# Decompilation imports...
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
# from ghidra.app.decompiler.clang import ClangTokenGroup
from ghidra.program.model.listing import CodeUnit

# FlatProgramAPI is optional, so we try to import it but don't fail if not present.
try:
    from ghidra.program.flatapi import FlatProgramAPI
except Exception:
    FlatProgramAPI = None


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


# TODO: Can remove after refactor.
gPM = currentProgram
gMEM = gPM.getMemory()
gSYMTAB = gPM.getSymbolTable()


PROGRAM = None
ADDRESS = None
MONITOR = None

# HELPERS FOR IMPORT Context.
def set_ctx(program=None, address=None, monitor=None):
    """Initialize context when called from the REPL or wrapper."""
       

    import __main__
    global PROGRAM, ADDRESS, MONITOR

    if program is None:
        program = getattr(__main__, 'currentProgram', None)
    if address is None:
        address = getattr(__main__, 'currentAddress', None)
    if monitor is None:
        monitor = getattr(__main__, 'monitor', None)
    if program is None:
        raise RuntimeError("DirtyDecompiler.set_ctx: supply program=currentProgram or run as a Ghidra script.")
    PROGRAM, ADDRESS, MONITOR = program, address, monitor

def _ensure_ctx():
    """Call at the start of any function that touches PROGRAM/ADDRESS/MONITOR."""
    if PROGRAM is None:
        set_ctx()  

def _comment_text_for_bits(bits_dict):
    # Produce a compact one-line comment listing bit names and masks
    pairs = ["%s=0x%X" % (k, v) for (k, v) in sorted(bits_dict.items(), key=lambda kv: kv[1])]
    return "Dirty430 bits: " + ", ".join(pairs)


# Script is idempotent by default, only creating labels/functions/data if missing.
# Set FORCE_OVERWRITE = True to allow the script to clear existing data/instructions
# in target regions before redefining them. Use with
# caution. You could screw up analysis Ghidra did already.
FORCE_OVERWRITE = False

# Verbose logging toggle: when True, log every skip/decision; when False, only key actions.
VERBOSE = True

# Stats..
_STAT = {
    'data_created': 0,
    'data_skipped_existing': 0,
    'data_skipped_overlap_data': 0,
    'data_skipped_instr': 0,
    'data_skipped_instr_overlap': 0,
    'ranges_cleared': 0,
}


# TODO: UGLY refactor some day.
def _addr_int(a):
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

    return "0x%X" % _addr_int(a)


# Found this somewhere on github and seemed good enough for our purposes. Had to make a 
# few changes.
def _log(msg, kind='info', always=False):
    """Internal logging wrapper: emits via Msg and also prints for the script console..."""

    if not VERBOSE and not always:
        # Still show final summary lines (they use always=True) but skip noisy items.
        return
    if kind == 'warn':
        Msg.warn(None, msg)
    elif kind == 'error':
        Msg.error(None, msg)
    else:
        Msg.info(None, msg)
    try:
        print(msg)
    except Exception:
        pass


def to_addr(addr):
    """Convert an integer to an Address object."""

    return gPM.getAddressFactory().getDefaultAddressSpace().getAddress(addr)


def mem_has(a_addr):
    """Check if memory contains the given address."""

    try:
        return gMEM.contains(to_addr(a_addr))
    except AddressOutOfBoundsException as e:
        Msg.error(None, "[!] Address out of bounds: %s" % e )
        return False


def apply_bitfield_comments():
    """Add EOL comments with bitfield names for known registers.

    Works for entries from both EMBEDDED_REGS and MSP430F5438_REG_BLOCKS.
    Returns count of annotations applied.
    """

    listing = gPM.getListing()
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

    # From the flat list
    # for addr, (name, _w) in EMBEDDED_REGS.items():
    #     applied += _annotate(addr, name)

    # From the structured blocks
    for base, blk in MSP430F5438_REG_BLOCKS.items():
        regs = blk.get('regs', [])
        for (name, off) in regs:
            applied += _annotate(base + off, name)

    return applied


def _infer_reg_width(name):
    """Return correct data width (1 or 2 bytes) for a given register name.

    MSP430F5438 has many 8‑bit USCI regs and 16‑bit others; this avoids
    overlapping words at odd addresses.
    """
    try:
        # Legacy SFR byte-sized mirrors (IE1/IFG1/ME1 and IE2/IFG2/ME2) are 8-bit
        if name in ('IE1', 'IFG1', 'ME1', 'IE2', 'IFG2', 'ME2'):
            return 1
        # Ports are bytes
        if name.startswith('P') and (len(name) >= 2 and name[1].isdigit()):
            return 1
        if name.startswith('PJ'):
            return 1
        # USCI (UART/SPI/I2C) are mostly bytes; IV is 16‑bit
        if name.startswith('UCA') or name.startswith('UCB'):
            return 2 if name.endswith('IV') else 1
        # ADC12 control are words; MCTL are bytes; MEM are words
        if name.startswith('ADC12MCTL'):
            return 1
        if name.startswith('ADC12MEM') or name.startswith('ADC12CTL'):
            return 2
        # Timer control/CCR/IV are words
        if name.endswith('IV') or name.endswith('EX0'):
            return 2
        if name.startswith('TA') or name.startswith('TB'):
            return 2
        # DMA ctl/size are words
        if name.startswith('DMA'):
            return 2
        # Default to word unless clearly byte‑typed
        return 2
    except Exception:
        return 2

# Addresses that come from the structured block map (authoritative). Used to skip
# duplicates from EMBEDDED_REGS that would collide or disagree on width.
_DEF_BLOCK_ADDRS = None


def _build_block_addr_set():
    global _DEF_BLOCK_ADDRS
    if _DEF_BLOCK_ADDRS is None:
        s = set()
        for base, blk in MSP430F5438_REG_BLOCKS.items():
            for (n, off) in blk.get('regs', []):
                s.add(base + off)
        _DEF_BLOCK_ADDRS = s
    return _DEF_BLOCK_ADDRS

def _build_block_covered_set():
    """Return a set of ALL byte addresses covered by register-block definitions.

    This includes both bytes of any 16-bit word so we can skip EMBEDDED_REGS
    entries that would land in the middle of a word (e.g., 0x0161).
    """
    covered = set()
    for base, blk in MSP430F5438_REG_BLOCKS.items():
        for (name, off) in blk.get('regs', []):
            addr = base + off
            w = _infer_reg_width(name)
            covered.add(addr)
            if w == 2:
                covered.add(addr + 1)
    return covered

def _build_canonical_name_addr_map():
    """Build a name->address map from the authoritative register blocks.

    Used to skip stale/incorrect entries in EMBEDDED_REGS whose names exist
    in the datasheet map but point at the wrong address (e.g., ADC12* at 0x0010..).
    """
    mapping = {}
    for base, blk in MSP430F5438_REG_BLOCKS.items():
        for (name, off) in blk.get('regs', []):
            mapping[name] = base + off
    return mapping

def _effective_width(addr, name, default_width):
    """Pick a safe width to prevent overlap.

    Also force byte at odd addresses to avoid straddling neighbors.
    """
    w = _infer_reg_width(name)
    # Never widen beyond the declared default; many legacy defs in EMBEDDED_REGS are byte-sized
    if default_width in (1, 2):
        if default_width < w:
            w = default_width
    # Never create 16-bit data on odd address; it would span a neighbor!!
    if (w == 2) and (addr & 1):
        _log("[warn] Forcing BYTE at odd %s for %s (was WORD)" % (fmt_addr(addr), name), 'warn')
        w = 1
    return w

def create_register_block_labels():
    """Create labels/data for MSP430F5438_REG_BLOCKS entries 
    
    We have (base + per-reg offsets).
    Idempotent and respects FORCE_OVERWRITE via make_data(). Returns count created/updated.
    """

    created = 0
    for base, blk in MSP430F5438_REG_BLOCKS.items():
        regs = blk.get('regs', [])
        for (name, off) in regs:
            a = base + off
            if not mem_has(a):
                continue
            # Use robust width inference.
            width = _infer_reg_width(name)
            make_data(a, width)
            make_label(a, name)
            created += 1

    return created


def make_data(addr, word_size):
    """Create data at the given address with the specified word size (1 or 2 bytes).

    Expands and clears any conflicting code/data units fully before insertion.
    Returns True if created, False if it already existed or failed.
    """
    a = to_addr(addr)
    end_addr = a.add(word_size - 1)

    def _addr_min(x, y):
        return x if x.compareTo(y) <= 0 else y

    def _addr_max(x, y):
        return x if x.compareTo(y) >= 0 else y

    def _expand_to_cover_conflicts(start, end):
        """If there is any containing data/instruction spanning the edges,

        expand [start,end] to fully cover them so clearListing removes the whole unit(s).
        """
        s, e = start, end
        d0 = getDataContaining(start)
        if d0 is not None:
            s = _addr_min(s, d0.getMinAddress()); e = _addr_max(e, d0.getMaxAddress())
        d1 = getDataContaining(end)
        if d1 is not None:
            s = _addr_min(s, d1.getMinAddress()); e = _addr_max(e, d1.getMaxAddress())
        i0 = getInstructionContaining(start)
        if i0 is not None:
            s = _addr_min(s, i0.getMinAddress()); e = _addr_max(e, i0.getMaxAddress())
        i1 = getInstructionContaining(end)
        if i1 is not None:
            s = _addr_min(s, i1.getMinAddress()); e = _addr_max(e, i1.getMaxAddress())
        return s, e

    existing_exact = getDataAt(a)
    existing_containing = getDataContaining(a)
    existing_instr = getInstructionAt(a)
    containing_instr = getInstructionContaining(a)

    # If anything already occupies these bytes, either clear (when FORCED) or skip
    if any(x is not None for x in (existing_exact, existing_containing, existing_instr, containing_instr)):
        if not FORCE_OVERWRITE:
            if existing_exact is not None:
                _STAT['data_skipped_existing'] += 1
            if existing_containing is not None and (existing_exact is None):
                _STAT['data_skipped_overlap_data'] += 1
            if existing_instr is not None:
                _STAT['data_skipped_instr'] += 1
            if containing_instr is not None and (existing_instr is None):
                _STAT['data_skipped_instr_overlap'] += 1
            return False
        # Expand clearing range to cover full conflicting units
        s, e = _expand_to_cover_conflicts(a, end_addr)
        try:
            clearListing(s, e)
            _log("[i] Cleared listing %s-%s for overwrite" % (fmt_addr(s), fmt_addr(e)))
            _STAT['ranges_cleared'] += 1
        except Exception as ce:
            _log("[!] Failed clearing %s-%s: %s" % (fmt_addr(s), fmt_addr(e), ce), 'warn', always=True)
            return False

    try:
        dt = WordDataType.dataType if word_size == 2 else ByteDataType.dataType
        createData(a, dt)
        _STAT['data_created'] += 1
        return True
    except Exception as e:
        # Print more context about the conflicting unit(s)
        d_cont = getDataContaining(a)
        i_cont = getInstructionContaining(a)
        rng = "%s..%s" % (fmt_addr(a), fmt_addr(end_addr))

        if d_cont is not None:
            _log("[!] Data conflict in %s vs existing DATA %s..%s (%s)" % (
                rng, fmt_addr(d_cont.getMinAddress()), fmt_addr(d_cont.getMaxAddress()), d_cont.getDataType().getName()), 'warn', always=True)

        if i_cont is not None:
            _log("[!] Data conflict in %s vs existing INSN %s..%s" % (
                rng, fmt_addr(i_cont.getMinAddress()), fmt_addr(i_cont.getMaxAddress())), 'warn', always=True)

        _log("[!] Failed to create data at %s: %s" % (fmt_addr(a), e), 'warn', always=True)
        return False

def make_label(addr, name):
    """Create a label at the given address with the specified name."""

    a_addr = to_addr(addr)
    Msg.info(None, "[i] Creating label %s at %s" % (name, fmt_addr(a_addr)))
    for s in gPM.getSymbolTable().getSymbols(a_addr):
        if s.getSource() == SourceType.USER_DEFINED:
            return False  # user label exists, skip

    createLabel(a_addr, name, True, SourceType.USER_DEFINED)
    return True

def install_msp430f5438_labels(program=None, logger=_log):
    """Create labels for MSP430F5438/5438A memory-mapped registers."""
    if program is None:
        try:
            _ensure_ctx()
            program = PROGRAM
        except Exception:
            raise RuntimeError("install_msp430f5438_labels: no program; call set_ctx(...) first")

    if FlatProgramAPI is None:
        raise RuntimeError("FlatProgramAPI not available")

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

    msg = "Dirty430: labeled {} MSP430F5438 registers".format(created)
    if logger:
        logger(msg)
    else:
        try: Msg.info(None, msg)
        except: print(msg)
    return created

def add_external_entry_point(addr):
    """Set external entry point at the given address."""
    a_addr = to_addr(addr)
    Msg.info(None, "[i] Adding external entry point at %s" % fmt_addr(a_addr))
    try:
        gPM.getSymbolTable().addExternalEntryPoint(a_addr)
        return True
    except Exception as e:
        Msg.warn(None, "[!] addExternalEntryPoint failed %s: %s" % (fmt_addr(a_addr), e))
        return False

def make_function(addr, name):
    """Create a function at the given address with the specified name."""

    a_addr = to_addr(addr)
    Msg.info(None, "[i] Creating function %s at %s" % (name, fmt_addr(a_addr)))
    if getFunctionAt(a_addr) is not None:
        Msg.info(None, "[i] Function already exists at %s" % fmt_addr(a_addr))
        return False

    createFunction(a_addr, name)
    Msg.info(None, "[i] Created function %s at %s" % (name, fmt_addr(a_addr)))
    return True


_VECTOR_HIGH_BYTES = tuple(range(16))


def _has_user_defined_symbol(addr_obj):
    """Return True if a user defined symbol exists at the address."""

    for symbol in gSYMTAB.getSymbols(addr_obj):
        if symbol.getSource() == SourceType.USER_DEFINED:
            return True
    return False

def _vector_label(addr):
    return "VEC_0x%04X" % addr

def _isr_label(addr):
    return "ISR_0x%04X" % addr

def _safe_short(addr_obj):
    try:
        return getShort(addr_obj) & 0xFFFF
    except Exception:
        return None


def _resolve_vector_target(low_word, has_mem):
    """
    Creates a clean 16-bit address for vector table.
    
    Helper. Will move into a class/func on refactor
    """

    for high in _VECTOR_HIGH_BYTES:
        candidate = (high << 16) | low_word
        if has_mem(candidate):
            return candidate
    return low_word if has_mem(low_word) else None


def install_reset_vector_info(addr):
    """Install reset vector info at the given address.
    
    TODO: Currently in main but refactor out and place
    here later. 
    """
    pass


def main():
    """Main function. """

    _log("======= Starting Dirty430 script!  =======\n\n")

    applied = 0
    _log("[*] Attempting to resolve/create vector functions/labels...")

    # Vectors region (0xFF80..0xFFFF) create words & label and attempt to resolve ISR targets
    # Handles 20-bit addresses by just resolving the low 16 bits for now...

    # TODO: Refactor this all into one function.
    mem_contains = mem_has
    to_address = to_addr
    for va in range(0xFF80, 0x10000, 2):
        if not mem_contains(va):
            continue

        addr_obj = to_address(va)

        # Data at vector entry
        if FORCE_OVERWRITE or getDataAt(addr_obj) is None:
            make_data(va, 2)

        # Add label (if missing)
        if FORCE_OVERWRITE or not _has_user_defined_symbol(addr_obj):
            make_label(va, _vector_label(va))

        low_word = _safe_short(addr_obj)
        if low_word is None:
            applied += 1
            continue

        # Resolve vector addr.
        resolved = _resolve_vector_target(low_word, mem_contains)
        if not resolved:
            applied += 1
            continue

        resolved_addr = to_address(resolved)
        isr_name = _isr_label(resolved)

        if FORCE_OVERWRITE or getFunctionAt(resolved_addr) is None:
            make_function(resolved, isr_name)

        make_label(resolved, isr_name)

        # Reset vector, create entry point
        if va == 0xFFFE:
            add_external_entry_point(resolved)

        applied += 1

    _log("[i] Created %d vector entries" % applied, always=True)

    # Now create memory mapped register labels... Reset counter.
    applied = 0
    _log("[i] Attempting to resolve/create embedded register labels and bitfields", always=True)

    block_addrs = _build_block_addr_set()
    block_cov = _build_block_covered_set()
    canon_by_name = _build_canonical_name_addr_map()
    # Insert more complete set of MSP430F5438 register labels
    applied += install_msp430f5438_labels(program=gPM, logger=_log)
    _log("[i] Created/updated %d MSP430F5438 register labels" % applied, always=True)

    # Create labels from the structured block map and annotate bitfields
    created_blk = create_register_block_labels()
    _log("[i] Created %d register-block labels" % created_blk, always=True)

    # Add bitfield comments
    annotated = apply_bitfield_comments()
    _log("[i] Added bitfield comments on %d regs" % annotated, always=True)

    # Summary statistics
    _log("\n======= Dirty430 Summary =======", always=True)
    _log("FORCE_OVERWRITE: %s" % FORCE_OVERWRITE, always=True)
    _log("VERBOSE: %s" % VERBOSE, always=True)
    _log("Data created: %d" % _STAT['data_created'], always=True)
    _log("Ranges cleared: %d" % _STAT['ranges_cleared'], always=True)
    _log("Skipped existing (exact): %d" % _STAT['data_skipped_existing'], always=True)
    _log("Skipped overlap data: %d" % _STAT['data_skipped_overlap_data'], always=True)
    _log("Skipped instruction exact: %d" % _STAT['data_skipped_instr'], always=True)
    _log("Skipped instruction overlap: %d" % _STAT['data_skipped_instr_overlap'], always=True)
    _log("================================\n", always=True)

    # Peace out homies..
    _log("[*] Finished Dirty430 PHASE 1!")

if __name__ == "__main__":
    main()
