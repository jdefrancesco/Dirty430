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



# Embedded memory mapped registers for the MSP430F5438.
# Hardcoded for now from the msp430f5438.h file.
EMBEDDED_REGS = {
    0x00010: ("ADC12MEM7", 2),
    0x00011: ("ADC12MEM8", 2),
    0x00012: ("ADC12MEM9", 2),
    0x00013: ("ADC12MEM10", 2),
    0x00014: ("ADC12MEM11", 2),
    0x00015: ("ADC12MEM12", 2),
    0x00016: ("ADC12MEM13", 2),
    0x00017: ("ADC12MEM14", 2),
    0x00018: ("ADC12MEM15", 2),
    0x00020: ("ADC12MEM0", 2),
    0x00022: ("ADC12MEM1", 2),
    0x00024: ("ADC12MEM2", 2),
    0x00026: ("ADC12MEM3", 2),
    0x00028: ("ADC12MEM4", 2),
    0x0002A: ("ADC12MEM5", 2),
    0x0002C: ("ADC12MEM6", 2),
    0x0002E: ("ADC12MEM7", 2),
    0x00040: ("ADC12CTL0", 2),
    0x00042: ("ADC12CTL1", 2),
    0x00044: ("ADC12CTL2", 2),
    0x00046: ("ADC12IFG", 2),
    0x00048: ("ADC12IE", 2),
    0x0004A: ("ADC12IV", 2),
    0x00080: ("TA0CTL", 2),
    0x00082: ("TA0CCTL0", 2),
    0x00084: ("TA0CCTL1", 2),
    0x00086: ("TA0CCTL2", 2),
    0x0008E: ("TA0R", 2),
    0x00090: ("TA0CCR0", 2),
    0x00092: ("TA0CCR1", 2),
    0x00094: ("TA0CCR2", 2),
    0x000A0: ("TA0IV", 2),
    0x000A2: ("TA0EX0", 2),
    0x00160: ("BCSCTL1", 1),
    0x00161: ("BCSCTL2", 1),
    0x00162: ("BCSCTL3", 1),
    0x0015C: ("WDTCTL", 2),
    0x00180: ("SYSCTL", 2),
    0x00182: ("SYSBSLC", 2),
    0x00200: ("P1IN", 1),
    0x00201: ("P1OUT", 1),
    0x00202: ("P1DIR", 1),
    0x00203: ("P1IFG", 1),
    0x00204: ("P1IES", 1),
    0x00205: ("P1IE", 1),
    0x00206: ("P1SEL", 1),
    0x00207: ("P1REN", 1),
    0x00208: ("P2IN", 1),
    0x00209: ("P2OUT", 1),
    0x0020A: ("P2DIR", 1),
    0x0020B: ("P2IFG", 1),
    0x0020C: ("P2IES", 1),
    0x0020D: ("P2IE", 1),
    0x0020E: ("P2SEL", 1),
    0x0020F: ("P2REN", 1),
    0x00210: ("P3IN", 1),
    0x00211: ("P3OUT", 1),
    0x00212: ("P3DIR", 1),
    0x00213: ("P3IFG", 1),
    0x00214: ("P3IES", 1),
    0x00215: ("P3IE", 1),
    0x00216: ("P3SEL", 1),
    0x00217: ("P3REN", 1),
    0x00218: ("P4IN", 1),
    0x00219: ("P4OUT", 1),
    0x0021A: ("P4DIR", 1),
    0x0021B: ("P4IFG", 1),
    0x0021C: ("P4IES", 1),
    0x0021D: ("P4IE", 1),
    0x0021E: ("P4SEL", 1),
    0x0021F: ("P4REN", 1),
    0x00220: ("P5IN", 1),
    0x00221: ("P5OUT", 1),
    0x00222: ("P5DIR", 1),
    0x00223: ("P5IFG", 1),
    0x00224: ("P5IES", 1),
    0x00225: ("P5IE", 1),
    0x00226: ("P5SEL", 1),
    0x00227: ("P5REN", 1),
    0x00228: ("P6IN", 1),
    0x00229: ("P6OUT", 1),
    0x0022A: ("P6DIR", 1),
    0x0022B: ("P6IFG", 1),
    0x0022C: ("P6IES", 1),
    0x0022D: ("P6IE", 1),
    0x0022E: ("P6SEL", 1),
    0x0022F: ("P6REN", 1),
    0x00230: ("P7IN", 1),
    0x00231: ("P7OUT", 1),
    0x00232: ("P7DIR", 1),
    0x00233: ("P7IFG", 1),
    0x00234: ("P7IES", 1),
    0x00235: ("P7IE", 1),
    0x00236: ("P7SEL", 1),
    0x00237: ("P7REN", 1),
    0x00238: ("P8IN", 1),
    0x00239: ("P8OUT", 1),
    0x0023A: ("P8DIR", 1),
    0x0023B: ("P8IFG", 1),
    0x0023C: ("P8IES", 1),
    0x0023D: ("P8IE", 1),
    0x0023E: ("P8SEL", 1),
    0x0023F: ("P8REN", 1),
    0x00240: ("P9IN", 1),
    0x00241: ("P9OUT", 1),
    0x00242: ("P9DIR", 1),
    0x00243: ("P9IFG", 1),
    0x00244: ("P9IES", 1),
    0x00245: ("P9IE", 1),
    0x00246: ("P9SEL", 1),
    0x00247: ("P9REN", 1),
    0x00248: ("P10IN", 1),
    0x00249: ("P10OUT", 1),
    0x0024A: ("P10DIR", 1),
    0x0024B: ("P10IFG", 1),
    0x0024C: ("P10IES", 1),
    0x0024D: ("P10IE", 1),
    0x0024E: ("P10SEL", 1),
    0x0024F: ("P10REN", 1),
    0x00320: ("P1IN", 1),
    0x00321: ("P1OUT", 1),
    0x00322: ("P1DIR", 1),
    0x00323: ("P1IFG", 1),
    0x00324: ("P1IES", 1),
    0x00325: ("P1IE", 1),
    0x00326: ("P1SEL", 1),
    0x00327: ("P1REN", 1),
    0x00328: ("P2IN", 1),
    0x00329: ("P2OUT", 1),
    0x0032A: ("P2DIR", 1),
    0x0032B: ("P2IFG", 1),
    0x0032C: ("P2IES", 1),
    0x0032D: ("P2IE", 1),
    0x0032E: ("P2SEL", 1),
    0x0032F: ("P2REN", 1),
    0x00340: ("TA1CTL", 2),
    0x00342: ("TA1CCTL0", 2),
    0x00344: ("TA1CCTL1", 2),
    0x00346: ("TA1CCTL2", 2),
    0x0034E: ("TA1R", 2),
    0x00350: ("TA1CCR0", 2),
    0x00352: ("TA1CCR1", 2),
    0x00354: ("TA1CCR2", 2),
    0x00360: ("TA1IV", 2),
    0x00400: ("UCA0CTL0", 1),
    0x00401: ("UCA0CTL1", 1),
    0x00402: ("UCA0BR0", 1),
    0x00403: ("UCA0BR1", 1),
    0x00404: ("UCA0MCTL", 1),
    0x00405: ("UCA0STAT", 1),
    0x00406: ("UCA0RXBUF", 1),
    0x00407: ("UCA0TXBUF", 1),
    0x00420: ("UCB0CTL0", 1),
    0x00421: ("UCB0CTL1", 1),
    0x00422: ("UCB0BR0", 1),
    0x00423: ("UCB0BR1", 1),
    0x00424: ("UCB0I2CIE", 1),
    0x00425: ("UCB0STAT", 1),
    0x00426: ("UCB0RXBUF", 1),
    0x00427: ("UCB0TXBUF", 1),
    0x005C0: ("UCA0CTL0", 1),
    0x005C1: ("UCA0CTL1", 1),
    0x005C2: ("UCA0BR0", 1),
    0x005C3: ("UCA0BR1", 1),
    0x005C4: ("UCA0MCTL", 1),
    0x005C5: ("UCA0STAT", 1),
    0x005C6: ("UCA0RXBUF", 1),
    0x005C7: ("UCA0TXBUF", 1),
    0x005E0: ("UCB0CTL0", 1),
    0x005E1: ("UCB0CTL1", 1),
    0x005E2: ("UCB0BR0", 1),
    0x005E3: ("UCB0BR1", 1),
    0x005E4: ("UCB0I2CIE", 1),
    0x005E5: ("UCB0STAT", 1),
    0x005E6: ("UCB0RXBUF", 1),
    0x005E7: ("UCB0TXBUF", 1),
    0x00600: ("MPY", 2),
    0x00602: ("MPYS", 2),
    0x00604: ("MAC", 2),
    0x00606: ("MACS", 2),
    0x00608: ("OP2", 2),
    0x0060A: ("RESV_MPY", 2),
    0x00700: ("FLASHCTL", 2),
    0x00702: ("FCTL1", 2),
    0x00704: ("FCTL2", 2),
    0x00706: ("FCTL3", 2),
    0x00800: ("DMACTL0", 2),
    0x00802: ("DMACTL1", 2),
    0x00804: ("DMACTL2", 2),
    0x00806: ("DMACTL3", 2),
    0x00808: ("DMACTL4", 2),
    0x0080A: ("DMACTL5", 2),
    0x0080C: ("DMA0CTL", 2),
    0x0080E: ("DMA0SA", 2),
    0x00810: ("DMA0DA", 2),
    0x00812: ("DMA0SZ", 2),
    0x00814: ("DMA1CTL", 2),
    0x00816: ("DMA1SA", 2),
    0x00818: ("DMA1DA", 2),
    0x0081A: ("DMA1SZ", 2),
    0x0081C: ("DMA2CTL", 2),
    0x0081E: ("DMA2SA", 2),
    0x00820: ("DMA2DA", 2),
    0x00822: ("DMA2SZ", 2),
    0x00F00: ("DEVID", 2),
    0x00F02: ("REVID", 1),
    0x00F10: ("SYSJTAGDIS", 1),
    0x00F12: ("SYSLOCK", 1),
    0x00F14: ("SYSRSTIV", 2),
    0x00F16: ("SYSRST", 1),
    0x00F18: ("SYSBSLC", 2),
    0x00F1A: ("SYSBERRIV", 2),
    0x00F1C: ("SYSBERR", 1),
    0x00F20: ("SFRIE1", 1),
    0x00F21: ("SFRIFG1", 1),
    0x00F22: ("SFRRPCR", 1),
    0x00F24: ("IE1", 1),
    0x00F25: ("IFG1", 1),
    0x00F26: ("ME1", 1),
    0x00F30: ("IE2", 1),
    0x00F31: ("IFG2", 1),
    0x00F32: ("ME2", 1),
    0x01000: ("RTCCTL", 2),
    0x01002: ("RTCIV", 2),
    0x01004: ("RTCSEC", 1),
    0x01005: ("RTCMIN", 1),
    0x01006: ("RTCHOUR", 1),
    0x01007: ("RTCDOW", 1),
    0x01008: ("RTCDAY", 1),
    0x01009: ("RTCMON", 1),
    0x0100A: ("RTCYEAR", 1),
    0x01010: ("RTCAMIN", 1),
    0x01011: ("RTCAHOUR", 1),
    0x01012: ("RTCADOW", 1),
    0x01013: ("RTCADAY", 1),
    0x01014: ("RTCAMON", 1),
    0x01015: ("RTCAYEAR", 1),
    0x01200: ("IE1", 1),
    0x01201: ("IFG1", 1),
    0x01202: ("ME1", 1),
    0x01210: ("IE2", 1),
    0x01211: ("IFG2", 1),
    0x01212: ("ME2", 1),
    0x01300: ("PORT_J_IN", 1),
    0x01301: ("PORT_J_OUT", 1),
    0x01302: ("PORT_J_DIR", 1),
    0x01303: ("PORT_J_IFG", 1),
    0x01304: ("PORT_J_IES", 1),
    0x01305: ("PORT_J_IE", 1),
    0x01306: ("PORT_J_SEL", 1),
    0x01307: ("PORT_J_REN", 1),
    0x01310: ("SYSBMS", 2),
    0x01312: ("UNUSED_1312", 1),
    0x01314: ("UNUSED_1314", 1),
    0x01400: ("MPY32L", 2),
    0x01402: ("MPY32H", 2),
    0x01404: ("MPYS32L", 2),
    0x01406: ("MPYS32H", 2),
    0x01408: ("MAC32L", 2),
    0x0140A: ("MAC32H", 2),
    0x0140C: ("OP2L", 2),
    0x0140E: ("OP2H", 2),
    0x02000: ("SFRIE1", 1),
    0x02002: ("SFRIFG1", 1),
    0x02004: ("SFRRPCR", 1),
    0x03040: ("TBCCTL0", 2),
    0x03042: ("TBCCTL1", 2),
    0x03044: ("TBCCTL2", 2),
    0x03046: ("TBCCTL3", 2),
    0x03048: ("TBCCTL4", 2),
    0x0304A: ("TBCCTL5", 2),
    0x0304C: ("TBCCTL6", 2),
    0x0304E: ("TBCTL", 2),
    0x03050: ("TBR", 2),
    0x03052: ("TBCCR0", 2),
    0x03054: ("TBCCR1", 2),
    0x03056: ("TBCCR2", 2),
    0x03058: ("TBCCR3", 2),
    0x0305A: ("TBCCR4", 2),
    0x0305C: ("TBCCR5", 2),
    0x0305E: ("TBCCR6", 2),
    0x03060: ("TBIV", 2),
    0x04000: ("USCI_A1_CTL0", 1),
    0x04001: ("USCI_A1_CTL1", 1),
    0x04002: ("USCI_A1_BR0", 1),
    0x04003: ("USCI_A1_BR1", 1),
    0x04004: ("USCI_A1_MCTL", 1),
    0x04005: ("USCI_A1_STAT", 1),
    0x04006: ("USCI_A1_RXBUF", 1),
    0x04007: ("USCI_A1_TXBUF", 1),
    0x04020: ("USCI_B1_CTL0", 1),
    0x04021: ("USCI_B1_CTL1", 1),
    0x04022: ("USCI_B1_BR0", 1),
    0x04023: ("USCI_B1_BR1", 1),
    0x04024: ("USCI_B1_I2CIE", 1),
    0x04025: ("USCI_B1_STAT", 1),
    0x04026: ("USCI_B1_RXBUF", 1),
    0x04027: ("USCI_B1_TXBUF", 1),
    0x04040: ("USCI_A2_CTL0", 1),
    0x04041: ("USCI_A2_CTL1", 1),
    0x04042: ("USCI_A2_BR0", 1),
    0x04043: ("USCI_A2_BR1", 1),
    0x04044: ("USCI_A2_MCTL", 1),
    0x04045: ("USCI_A2_STAT", 1),
    0x04046: ("USCI_A2_RXBUF", 1),
    0x04047: ("USCI_A2_TXBUF", 1),
    0x04060: ("USCI_B2_CTL0", 1),
    0x04061: ("USCI_B2_CTL1", 1),
    0x04062: ("USCI_B2_BR0", 1),
    0x04063: ("USCI_B2_BR1", 1),
    0x04064: ("USCI_B2_I2CIE", 1),
    0x04065: ("USCI_B2_STAT", 1),
    0x04066: ("USCI_B2_RXBUF", 1),
    0x04067: ("USCI_B2_TXBUF", 1),
    0x05000: ("CRC32CTL", 2),
    0x05002: ("CRC32INI", 2),
    0x05004: ("CRC32RES", 2),
    0x06000: ("TEMP_SENSOR", 1),
    0x07000: ("UNUSED_7000", 1),
    0x0F000: ("DEVID_ALT", 2),
    0x0F002: ("REVID_ALT", 1),
}


gPM = currentProgram
gMEM = gPM.getMemory()
gSYMTAB = gPM.getSymbolTable()


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


def make_data(addr, word_size):
    """Create data at the given address with the specified word size (1 or 2 bytes).
    Returns True if created, False if it already existed or failed."""

    a = to_addr(addr)
    end_addr = a.add(word_size - 1)
    existing_exact = getDataAt(a)
    existing_containing = getDataContaining(a)
    existing_instr = getInstructionAt(a)
    containing_instr = getInstructionContaining(a)

    def _clear_range():
        try:
            clearListing(a, end_addr)
            _log("[i] Cleared listing %s-%s for overwrite" % (fmt_addr(a), fmt_addr(end_addr)))
            _STAT['ranges_cleared'] += 1
            return True
        except Exception as ce:
            _log("[!] Failed clearing %s-%s: %s" % (fmt_addr(a), fmt_addr(end_addr), ce), 'warn', always=True)
            _log("[i] Skipping data at %s (already exact)" % fmt_addr(a))
            return False

    # Existing data exact
    if existing_exact is not None:
        if FORCE_OVERWRITE:
            if not _clear_range():
                return False
        else:
            _STAT['data_skipped_existing'] += 1
            return False

    # Containing data
    if existing_containing is not None and existing_containing.getMinAddress() != a:
        if FORCE_OVERWRITE:
            if not _clear_range():
                return False
        else:
            _log("[i] Skipping data at %s (inside existing %s at %s)" % (
                fmt_addr(a), existing_containing.getDataType().getName(), fmt_addr(existing_containing.getMinAddress())))
            _STAT['data_skipped_overlap_data'] += 1
            return False

    # Instruction overlap
    if existing_instr is not None:
        if FORCE_OVERWRITE:
            if not _clear_range():
                return False
        else:
            _log("[i] Skipping data at %s (instruction already present)" % fmt_addr(a))
            _STAT['data_skipped_instr'] += 1
            return False

    if containing_instr is not None and containing_instr.getMinAddress() != a:
        if FORCE_OVERWRITE:
            if not _clear_range():
                return False
        else:
            Msg.info(None, "[i] Skipping data at %s (inside instruction at %s)" % (
                fmt_addr(a), fmt_addr(containing_instr.getMinAddress())))
            _STAT['data_skipped_instr_overlap'] += 1
            return False

    try:
        createData(a, WordDataType.dataType if word_size == 2 else ByteDataType.dataType)
        _STAT['data_created'] += 1
        return True
    except Exception as e:
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


def main():
    """Main function... """

    Msg.info(None, "======= Starting Dirty430 script!  =======\n\n")

    applied = 0
    Msg.info(None, "[*] Attempting to resolve/create vector functions/labels...")

    # Vectors region (0xFF80..0xFFFF) create words & label and attempt to resolve ISR targets
    # Handles 20-bit addresses by just resolving the low 16 bits for now...
    # TODO: Refactor ugliness
    for va in range(0xFF80, 0x10000, 2):
        if not mem_has(va):
            continue

        # Data at vector entry
        if FORCE_OVERWRITE or getDataAt(to_addr(va)) is None:
            make_data(va, 2)

        # Add label (if missing)
        if FORCE_OVERWRITE or not any(s.getSource() == SourceType.USER_DEFINED for s in gSYMTAB.getSymbols(to_addr(va))):
            make_label(va, "VEC_0x%04X" % va)

        try:
            low = getShort(to_addr(va)) & 0xFFFF
        except:
            low = None

        if low is not None:
            resolved = None
            for hb in range(0, 16):  # Check high byte possibilities
                cand = (hb << 16) | low
                if mem_has(cand):
                    resolved = cand
                    break
            if resolved is None and mem_has(low):
                resolved = low  # Maybe it's just a 16-bit address

            if resolved:
                if FORCE_OVERWRITE or getFunctionAt(to_addr(resolved)) is None:
                    make_function(resolved, "ISR_0x%04X" % resolved)

                make_label(resolved, "ISR_0x%04X" % resolved)

                if va == 0xFFFE:
                    # Reset vector, create entry point
                    add_external_entry_point(resolved)

        applied += 1

    _log("[i] Created %d vector entries" % applied, always=True)

    # Now creeate memory mapped registers... Reset counter.
    applied = 0
    _log("[i] Attempting to resolve/create embedded register labels...", always=True)
    for addr, (name, width) in EMBEDDED_REGS.items():
        if not mem_has(addr):
            continue

        make_data(addr, width)

        if FORCE_OVERWRITE or not any(s.getSource() == SourceType.USER_DEFINED for s in gPM.getSymbolTable().getSymbols(to_addr(addr))):
            make_label(addr, name)

        applied += 1

    _log("[i] Created %d embedded register entries" % applied, always=True)

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
    Msg.info(None, "[*] Finished Dirty430 PHASE 1!")

if __name__ == "__main__":
    main()
