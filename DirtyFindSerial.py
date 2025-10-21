# DirtyFindSerial.py
# MSP430F5438 all-in-one:
#  - SPI TX/RX transaction detection split by Chip Select (CS) on PxOUT (auto-detected)
#  - Exports each SPI TX burst to ~/Desktop/ghidra_exports/*.bin
#  - Flags RX activity (values unknown statically)
#  - Heuristic fallback when CS cannot be inferred
#  - Parallel/GPIO burst detection (likely FPGA/display)
#  - Basic DMA usage detection
#
# Run from Ghidra Script Manager with your MSP430F5438 firmware loaded.

#@author J. DeFrancesco
#@category MSP430

from collections import deque, defaultdict
from ghidra.program.model.symbol import SourceType
from java.io import File, FileOutputStream
import os, time


# USCI registers (F5438)
USCI_REGS = {
    0x05C0: "UCB0CTL1", 0x05C1: "UCB0CTL0", 0x05C2: "UCB0BR0", 0x05C3: "UCB0BR1",
    0x05C6: "UCB0I2CSA", 0x05C7: "UCB0RXBUF", 0x05C8: "UCB0TXBUF",
    0x05E0: "UCB1CTL1", 0x05E1: "UCB1CTL0", 0x05E6: "UCB1I2CSA", 0x05E7: "UCB1RXBUF", 0x05E8: "UCB1TXBUF",
    0x05D0: "UCA0CTL1", 0x05D1: "UCA0CTL0", 0x05D7: "UCA0RXBUF", 0x05D8: "UCA0TXBUF",
    0x05F0: "UCA1CTL1", 0x05F1: "UCA1CTL0", 0x05F7: "UCA1RXBUF", 0x05F8: "UCA1TXBUF",
}

# Treat these as SPI TX/RX buffers
SPI_TXBUF_ADDRS = set([0x05C8, 0x05E8, 0x05D8, 0x05F8])
SPI_RXBUF_ADDRS = set([0x05C7, 0x05E7, 0x05D7, 0x05F7])

# MSP430F5438 PxOUT addresses (per TI datasheet)
PXOUT_ADDRS = {
    0x0021: "P1OUT",
    0x0029: "P2OUT",
    0x0019: "P3OUT",
    0x001D: "P4OUT",
    0x0031: "P5OUT",
    0x0035: "P6OUT",
    0x0039: "P7OUT",
    0x003B: "P8OUT",
    0x003D: "P9OUT",
    0x003F: "P10OUT",
}
PXOUT_SET = set(PXOUT_ADDRS.keys())

# Peripheral window
PERIPH_LO = 0x0000
PERIPH_HI = 0x0FFF

# DMA controller window for F5xx
DMA_LO = 0x0500
DMA_HI = 0x051F

# Heuristics / thresholds
SPI_MIN_TX_IN_BURST = 6     # min TX writes to call it a SPI burst
CS_LINK_WINDOW       = 20   # instr distance to associate PxOUT write with TX start/stop
PARALLEL_MIN_WRITES  = 8    # min writes to same periph addr to export as "parallel" burst
SLIDE_WINDOW         = 24   # window for grouping writes
# =========================================

def ensure_export_dir():
    if not os.path.exists(EXPORT_DIR):
        os.makedirs(EXPORT_DIR)
    return EXPORT_DIR

def to_addr(x):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x)

def set_label(addr, name, comment):
    st = currentProgram.getSymbolTable()
    sym = st.getPrimarySymbol(addr)
    if sym is None or sym.getName() != name:
        st.createLabel(addr, name, SourceType.USER_DEFINED)
    if comment:
        setEOLComment(addr, comment)

def label_usci_and_ports():
    for off, n in USCI_REGS.items():
        set_label(to_addr(off), n, "USCI %s" % n)
    for off, n in PXOUT_ADDRS.items():
        set_label(to_addr(off), n, "GPIO %s" % n)

def addr_of_op(op):
    try:
        a = op.toAddress()
        if a:
            return int(a.getOffset())
    except:
        pass
    return None

def scalar_value(obj):
    try:
        from ghidra.program.model.scalar import Scalar
        if isinstance(obj, Scalar):
            return int(obj.getValue())
    except:
        pass
    try:
        v = getattr(obj, "getValue", None)
        if callable(v):
            return int(v())
    except:
        pass
    return None

def is_write(instr):
    m = instr.getMnemonicString().upper()
    return (m.startswith("MOV") or m.startswith("ST") or m.startswith("STR")
            or m.startswith("BIS") or m.startswith("BIC") or m.startswith("MOVX"))

def is_read(instr):
    # MOV from mem to reg
    m = instr.getMnemonicString().upper()
    return m.startswith("MOV")

def dest_addr(instr):
    try:
        ops1 = list(instr.getOpObjects(1))
    except:
        ops1 = []
    for o in ops1:
        off = addr_of_op(o)
        if off is not None:
            return off
    return None

def src_addr(instr):
    try:
        ops0 = list(instr.getOpObjects(0))
    except:
        ops0 = []
    for o in ops0:
        off = addr_of_op(o)
        if off is not None:
            return off
    return None

def extract_tx_byte(instr, instrs):
    # Try immediate in source
    try:
        ops0 = list(instr.getOpObjects(0))
    except:
        ops0 = []
    for s in ops0:
        v = scalar_value(s)
        if v is not None:
            return v & 0xFF
    # Backward small search for MOV #imm, Rn then MOV Rn, &TXBUF
    idx = instrs.index(instr)
    for back in range(1, 9):
        j = idx - back
        if j < 0:
            break
        cand = instrs[j]
        if not cand.getMnemonicString().upper().startswith("MOV"):
            continue
        try:
            src0 = list(cand.getOpObjects(0))
            dst1 = list(cand.getOpObjects(1))
            src_now = list(instr.getOpObjects(0))
        except:
            continue
        if not src0 or not dst1 or not src_now:
            continue
        imm = scalar_value(src0[0])
        if imm is None:
            continue
        # match register names
        try:
            dstname = dst1[0].getName()
            for s in src_now:
                try:
                    if s.getName() == dstname:
                        return imm & 0xFF
                except:
                    pass
        except:
            pass
    return None

def write_bin(buf, fname):
    p = os.path.join(EXPORT_DIR, fname)
    fos = FileOutputStream(File(p))
    try:
        fos.write(bytearray(buf))
        print("  -> wrote %d bytes to %s" % (len(buf), p))
    finally:
        fos.close()

def find_cs_around(instrs, idx_first_tx, idx_last_tx):
    # Look for PxOUT writes near burst boundaries.
    # Return (cs_addr, before_instr_addr, after_instr_addr), or (None, None, None)
    lo = max(0, idx_first_tx - CS_LINK_WINDOW)
    hi = min(len(instrs) - 1, idx_last_tx + CS_LINK_WINDOW)
    before = None
    after = None
    cs_addr = None
    # find first PxOUT write before burst
    for i in range(idx_first_tx - 1, lo - 1, -1):
        d = dest_addr(instrs[i])
        if d in PXOUT_SET:
            before = instrs[i].getAddress()
            cs_addr = d
            break
    # find first PxOUT write after burst (same addr preferred)
    if cs_addr is not None:
        for i in range(idx_last_tx + 1, hi + 1):
            d = dest_addr(instrs[i])
            if d == cs_addr:
                after = instrs[i].getAddress()
                break
    else:
        # fallback: any PxOUT after
        for i in range(idx_last_tx + 1, hi + 1):
            d = dest_addr(instrs[i])
            if d in PXOUT_SET:
                cs_addr = d
                after = instrs[i].getAddress()
                break
    return cs_addr, before, after

def detect_spi_transactions():
    print("Scanning for SPI transactions (CS-split, TX/RX awareness)...")
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    exports = []

    for func in fm.getFunctions(True):
        instrs = list(listing.getInstructions(func.getBody(), True))
        if not instrs:
            continue

        i = 0
        while i < len(instrs):
            # Find a TX to start
            if dest_addr(instrs[i]) in SPI_TXBUF_ADDRS:
                # Grow contiguous TXBUF write run
                start = i
                end = i
                while end + 1 < len(instrs) and dest_addr(instrs[end + 1]) in SPI_TXBUF_ADDRS:
                    end += 1
                # Only consider if reasonably sized (or try smaller if CS found)
                tx_count = end - start + 1
                # Try to find CS around this run
                cs_addr, cs_before, cs_after = find_cs_around(instrs, start, end)

                # If CS found: treat everything from start to the matching after-CS as one transaction; collect TX inside
                if cs_addr is not None:
                    # Expand forward until first write to same cs_addr (if not already matched)
                    j = end + 1
                    last = end
                    while j < len(instrs):
                        if dest_addr(instrs[j]) == cs_addr:
                            last = j - 1
                            break
                        j += 1
                    if j >= len(instrs):
                        last = end
                    # Collect TX bytes and detect RX reads within [start, last]
                    bytes_out = []
                    rx_reads = 0
                    k = start
                    while k <= last:
                        if dest_addr(instrs[k]) in SPI_TXBUF_ADDRS:
                            b = extract_tx_byte(instrs[k], instrs)
                            if b is None:
                                b = 0x00
                            bytes_out.append(b)
                        if src_addr(instrs[k]) in SPI_RXBUF_ADDRS:
                            rx_reads += 1
                        k += 1
                    # Export even if small, since CS bound is strong
                    ts = int(time.time())
                    fname = "spi_tx_%s_%s_%d.bin" % (func.getName(), instrs[start].getAddress(), ts)
                    fname = fname.replace(":", "_").replace(" ", "_")
                    write_bin(bytes_out, fname)
                    try:
                        tag = "%s (CS=%s)" % (PXOUT_ADDRS.get(cs_addr, "PxOUT"), hex(cs_addr))
                        setEOLComment(instrs[start].getAddress(), "SPI TX %d bytes, %s, RX-reads=%d" % (len(bytes_out), tag, rx_reads))
                    except:
                        pass
                    exports.append((func.getName(), instrs[start].getAddress(), len(bytes_out), cs_addr, rx_reads))
                    i = last + 1
                    continue

                # If no CS found: fallback to contiguous burst threshold
                if tx_count >= SPI_MIN_TX_IN_BURST:
                    bytes_out = []
                    for k in range(start, end + 1):
                        b = extract_tx_byte(instrs[k], instrs)
                        if b is None:
                            b = 0x00
                        bytes_out.append(b)
                    ts = int(time.time())
                    fname = "spi_tx_%s_%s_%d.bin" % (func.getName(), instrs[start].getAddress(), ts)
                    fname = fname.replace(":", "_").replace(" ", "_")
                    write_bin(bytes_out, fname)
                    try:
                        setEOLComment(instrs[start].getAddress(), "SPI TX burst %d bytes (no-CS)" % len(bytes_out))
                    except:
                        pass
                    exports.append((func.getName(), instrs[start].getAddress(), len(bytes_out), None, 0))
                    i = end + 1
                    continue

            i += 1

    print("SPI transactions exported: %d" % len(exports))
    return exports

def detect_parallel_bursts():
    print("Scanning for parallel/GPIO bursts...")
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    exports = []

    for func in fm.getFunctions(True):
        instrs = list(listing.getInstructions(func.getBody(), True))
        if not instrs:
            continue
        window = deque(maxlen=SLIDE_WINDOW)
        for instr in instrs:
            window.append(instr)
            periph_map = defaultdict(list)
            for w in window:
                d = dest_addr(w)
                if d is None or not (PERIPH_LO <= d <= PERIPH_HI):
                    continue
                val = None
                try:
                    ops0 = list(w.getOpObjects(0))
                    if ops0:
                        vv = scalar_value(ops0[0])
                        if vv is not None:
                            val = vv & 0xFF
                except:
                    pass
                periph_map[d].append((w, val))
            for a, lst in periph_map.items():
                if len(lst) >= PARALLEL_MIN_WRITES:
                    vals = [ (v if v is not None else 0) for (_, v) in lst ]
                    ts = int(time.time())
                    fname = "parallel_%s_%04X_%d.bin" % (func.getName(), a, ts)
                    write_bin(vals, fname)
                    try:
                        setEOLComment(lst[0][0].getAddress(), "Parallel burst to 0x%04X (%d writes)" % (a, len(vals)))
                    except:
                        pass
                    exports.append((func.getName(), a, len(vals)))
                    window.clear()
                    break
    print("Parallel bursts exported: %d" % len(exports))
    return exports

def detect_dma_usage():
    print("Scanning DMA usage...")
    fm = currentProgram.getFunctionManager()
    listing = currentProgram.getListing()
    st = currentProgram.getSymbolTable()

    dma_symbols = []
    for s in st.getAllSymbols(True):
        try:
            n = s.getName()
            if n and ("DMA" in n.upper() or "UDMA" in n.upper()):
                dma_symbols.append((n, s.getAddress()))
        except:
            pass

    dma_funcs = set()
    for func in fm.getFunctions(True):
        hit = False
        for instr in listing.getInstructions(func.getBody(), True):
            d = dest_addr(instr)
            if d is not None and DMA_LO <= d <= DMA_HI:
                setEOLComment(instr.getAddress(), "DMA reg access")
                hit = True
        if hit:
            dma_funcs.add(func.getName())

    print("DMA symbols: %d; functions touching DMA regs: %d" % (len(dma_symbols), len(dma_funcs)))
    return dma_symbols, list(dma_funcs)

def main():
    print("=== D430 MSP430F5438 Serial Detector ===")
    ensure_export_dir()
    label_usci_and_ports()

    spi = detect_spi_transactions()
    par = detect_parallel_bursts()
    dma_syms, dma_funcs = detect_dma_usage()

    print("\n=== Summary ===")
    print("SPI transactions: %d" % len(spi))
    for (fn, a, n, cs, rxn) in spi:
        cs_str = PXOUT_ADDRS.get(cs, "unknown") if cs is not None else "no-CS"
        print(" - %s @ %s : %d bytes, CS=%s, RX-reads=%d" % (fn, a, n, cs_str, rxn))

    print("Parallel bursts: %d" % len(par))
    for (fn, addr, cnt) in par:
        print(" - %s -> 0x%04X (%d writes)" % (fn, addr, cnt))

    print("DMA symbols: %d" % len(dma_syms))
    for (n, a) in dma_syms:
        print(" - %s @ %s" % (n, a))

    print("DMA functions: %d" % len(dma_funcs))
    for fn in dma_funcs:
        print(" - %s" % fn)

    print("=== Done ===")

if __name__ == "__main__":
    main()