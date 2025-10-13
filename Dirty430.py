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

# Embedded memory mapped registers for the MSP430F5438.
# Hardcoded for now from the msp430f5438.h file.
# See MSP430F5438 datasheet for more details.
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

# Selected high-signal regs we see a lot in firmware. Values are masks; multi-bit
# fields are represented by individual bit positions (e.g., SELA0/1/2).
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



gPM = currentProgram
gMEM = gPM.getMemory()
gSYMTAB = gPM.getSymbolTable()


PROGRAM = None
ADDRESS = None
MONITOR = None

# HELPERS FOR IMPORT CONTEST
def set_ctx(program=None, address=None, monitor=None):
    """Initialize context when called from the REPL or wrapper.
       If args are None, try to pull from __main__ (REPL/script env)."""

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
    for addr, (name, _w) in EMBEDDED_REGS.items():
        applied += _annotate(addr, name)

    # From the structured blocks
    for base, blk in MSP430F5438_REG_BLOCKS.items():
        regs = blk.get('regs', [])
        for (name, off) in regs:
            applied += _annotate(base + off, name)

    return applied


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
            # Prefer correct width: most are 16-bit words, but some are bytes in these blocks.
            # Heuristic: treat names ending in _L/_H or port IN/OUT/DIR/REN/SEL as bytes; else word.
            width = 1 if name.endswith('_L') or name.endswith('_H') or name.startswith('P') else 2
            make_data(a, width)
            make_label(a, name)
            created += 1
    return created



# Script is idempotent by default, only creating labels/functions/data if missing.
# Set FORCE_OVERWRITE = True to allow the script to clear existing data/instructions
# in target regions before redefining them. Use with
# caution. You could screw up analysis Ghidra did already.
FORCE_OVERWRITE = True

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

def install_msp430f5438_labels(program=None, logger=None):
    """Create labels for MSP430F5438/5438A memory-mapped registers.

    - program: defaults to Dirty430.PROGRAM via set_ctx()
    - logger: optional callable(msg); falls back to Msg/print
    """
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
    """Main function... """

    Msg.info(None, "======= Starting Dirty430 script!  =======\n\n")

    applied = 0
    Msg.info(None, "[*] Attempting to resolve/create vector functions/labels...")

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

        resolved = _resolve_vector_target(low_word, mem_contains)
        if not resolved:
            applied += 1
            continue

        resolved_addr = to_address(resolved)
        isr_name = _isr_label(resolved)

        if FORCE_OVERWRITE or getFunctionAt(resolved_addr) is None:
            make_function(resolved, isr_name)

        make_label(resolved, isr_name)

        if va == 0xFFFE:
            # Reset vector, create entry point
            add_external_entry_point(resolved)

        applied += 1

    _log("[i] Created %d vector entries" % applied, always=True)

    # Now create memory mapped register labels... Reset counter.
    applied = 0
    _log("[i] Attempting to resolve/create embedded register labels and bitfields", always=True)
    for addr, (name, width) in EMBEDDED_REGS.items():
        if not mem_has(addr):
            continue
        make_data(addr, width)
        if FORCE_OVERWRITE or not any(s.getSource() == SourceType.USER_DEFINED for s in gPM.getSymbolTable().getSymbols(to_addr(addr))):
            make_label(addr, name)
        applied += 1

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
    Msg.info(None, "[*] Finished Dirty430 PHASE 1!")

if __name__ == "__main__":
    main()
