# DirtyDetectCrypto.py
#
#
# - RC4 (256-byte permutation detection, KSA/PRGA heuristics, key extraction, KSA emulation verification)
# - AES S-box / invS-box / Rcon detection
# - XTEA/TEA heuristics (constants and ARX patterns)
# - CRC table heuristics
# - PRNG detection (Knuth subtractive, NR ran1, RANDU, glibc LCG)
# - Correlation with radio I/O (UCAx/UCBx TX/RXBUF, P1OUT..P4OUT)
# - Adds Bookmarks and Plate comments (no renaming/modification)

from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.symbol import SourceType
from javax.swing import JOptionPane, JScrollPane, JTextArea

import re, time, struct, binascii

#
BOOKMARK_CRYPTO = "CRYPTO"
BOOKMARK_RC4    = "RC4_KSA"
BOOKMARK_PRNG   = "PRNG"
BOOKMARK_CRYPTO_IO = "CRYPTO_IO"
MAX_CHUNK = 0x10000
DECOMP_TIMEOUT = 6
KEY_READ_MAX = 64
# MSP430 register addresses commonly used (approx for MSP430F5438 family)
IO_REGS = {
    "UCA0RXBUF": 0x05cc,
    "UCA0TXBUF": 0x05ce,

    "UCB0RXBUF": 0x05ec,
    "UCB0TXBUF": 0x05ee,

    "UCB1RXBUF": 0x062c,
    "UCB1TXBUF": 0x062e,

    "P1OUT": 0x0021,
    "P2OUT": 0x0029,
    "P3OUT": 0x0019,
    "P4OUT": 0x001d
}
# crypto signatures
AES_SBOX_HEAD = [0x63,0x7c,0x77,0x7b]
AES_INV_HEAD  = [0x52,0x09,0x6a,0xd5]
AES_RCON_SEQ  = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
TEA_DELTA     = 0x9E3779B9
TEA_SUM32     = 0xC6EF3720
CRC32_POLY    = 0xEDB88320
CRC16_POLYS   = [0x1021, 0xA001]
# PRNG constants
PM_IA = 16807
PM_IM = 2147483647
PM_IQ = 127773
PM_IR = 2836
KNUTH_MBIG = 1000000000
KNUTH_MSEED = 161803398
KNUTH_N = 55
KNUTH_LAG = 24

# regex heuristics
RE_FOR_256 = re.compile(r'\bfor\b[^;]*;\s*i\s*<\s*256\b', re.IGNORECASE)
RE_MASK_0xFF = re.compile(r'&\s*0x?ff\b', re.IGNORECASE)
RE_KEY_MOD = re.compile(r'([A-Za-z_0-9]+)\s*\[\s*i\s*%\s*([0-9A-Za-z_]+)\s*\]', re.IGNORECASE)
RE_KEY_SIMPLE = re.compile(r'([A-Za-z_0-9]+)\s*\[\s*i\s*\]', re.IGNORECASE)
RE_SWAP = re.compile(r'swap\s*\(|tmp\s*=.*s\[', re.IGNORECASE)
RE_PRGA_I = re.compile(r'i\s*=\s*\(?i\s*\+\s*1\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_J = re.compile(r'j\s*=\s*\(?j\s*\+\s*s\[\s*i\s*\]\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_OUT = re.compile(r'\^\s*s\[\s*\(s\[.*i.*\]\s*\+\s*s\[.*j.*\]\s*\)\s*&\s*0x?ff', re.IGNORECASE)
RE_XTEA_ARX = re.compile(r'<<\s*4|>>\s*5|0x9e3779b9', re.IGNORECASE)
RE_PRNG_PM = re.compile(r'16807|127773|2836|0x41a7|0x1f31d|0x0b14', re.IGNORECASE)
RE_PRNG_KNUTH = re.compile(r'161803398|1000000000|55|24', re.IGNORECASE)
RE_LCG = re.compile(r'1103515245|12345|65539|0x41c64e6d|0x3039|0x00010003', re.IGNORECASE)

# ghidra objects
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
bkm = currentProgram.getBookmarkManager()
fm = currentProgram.getFunctionManager()
symtab = currentProgram.getSymbolTable()
refmgr = currentProgram.getReferenceManager()


def note(addr, category, kind, msg):
    """Add bookmark and plate comment; print summary."""
    try:
        bkm.setBookmark(addr, category, kind, msg)
    except:
        pass
    try:
        listing.setComment(addr, CodeUnit.PLATE_COMMENT, "[%s] %s" % (category, msg))
    except:
        pass
    print("%s | %s @ %s : %s" % (category, kind, addr.toString(), msg))

def read_bytes(addr, length):
    try:
        buf = bytearray(length)
        memory.getBytes(addr, buf)
        return buf
    except MemoryAccessException:
        return None
    except Exception:
        return None

def u32_le(buf, i):
    if i + 4 > len(buf): 
        return None
    return (buf[i] | (buf[i+1]<<8) | (buf[i+2]<<16) | (buf[i+3]<<24)) & 0xffffffff

def is_256_permutation(buf, offset=0):
    if buf is None: return False
    if offset + 256 > len(buf): return False
    seen = [False]*256
    for i in range(256):
        v = buf[offset+i]
        if seen[v]:
            return False
        seen[v] = True
    return True

def find_256_tables():
    """Find all 256-byte permutation tables in initialized memory blocks."""

    results = []
    blocks = memory.getBlocks()
    for blk in blocks:
        if not blk.isInitialized(): continue
        start = blk.getStart()
        size = blk.getSize()
        off = 0
        while off < size:
            chunk = MAX_CHUNK if (size - off) > MAX_CHUNK else (size - off)
            base = start.add(off)
            bb = read_bytes(base, chunk)
            if bb is None:
                off += chunk
                continue
            i = 0; L = len(bb)
            while i + 256 <= L:
                if is_256_permutation(bb, i):
                    addr = base.add(i)
                    results.append(addr)
                    note(addr, BOOKMARK_CRYPTO, "Table", "256-byte permutation (S[] candidate)")
                    i += 256
                    continue
                i += 1
            off += chunk
    return results

def find_aes_rcon_and_sboxes():
    """Find AES S-box, inverse S-box, and Rcon sequences in memory."""

    hits = []
    blocks = memory.getBlocks()
    for blk in blocks:
        if not blk.isInitialized(): continue
        start = blk.getStart(); size = blk.getSize()
        off = 0
        while off < size:
            chunk = MAX_CHUNK if (size - off) > MAX_CHUNK else (size - off)
            base = start.add(off)
            bb = read_bytes(base, chunk)
            if bb is None:
                off += chunk; continue
            # check for sbox and inv headers
            for i in range(0, len(bb)-4+1):
                if bb[i:i+4] == bytearray(AES_SBOX_HEAD):
                    a = base.add(i); hits.append((a, "AES_SBOX")); note(a, BOOKMARK_CRYPTO, "AES", "AES S-box header")
                if bb[i:i+4] == bytearray(AES_INV_HEAD):
                    a = base.add(i); hits.append((a, "AES_INV")); note(a, BOOKMARK_CRYPTO, "AES", "AES inverse S-box header")
                # rcon
                if i + len(AES_RCON_SEQ) <= len(bb):
                    ok = True
                    for j in range(len(AES_RCON_SEQ)):
                        if bb[i+j] != AES_RCON_SEQ[j]:
                            ok = False; break
                    if ok:
                        a = base.add(i); hits.append((a, "AES_RCON")); note(a, BOOKMARK_CRYPTO, "AES", "AES Rcon sequence")
            off += chunk
    return hits

def find_crc32_tables():
    """Find possible CRC32 tables in memory."""

    hits = []
    blocks = memory.getBlocks()
    for blk in blocks:
        if not blk.isInitialized(): continue
        start = blk.getStart(); size = blk.getSize()
        off = 0
        while off < size:
            chunk = MAX_CHUNK if (size - off) > MAX_CHUNK else (size - off)
            base = start.add(off)
            bb = read_bytes(base, chunk)
            if bb is None:
                off += chunk; continue
            L = len(bb)
            i = 0
            while i + 1024 <= L:  # 256*4
                # quick heuristic: not all zero
                some_nonzero = False
                for k in range(0, 1024, 4):
                    v = u32_le(bb, i+k)
                    if v is None: break
                    if v != 0:
                        some_nonzero = True; break
                if some_nonzero:
                    a = base.add(i)
                    hits.append(a)
                    note(a, BOOKMARK_CRYPTO, "CRC", "Possible 256x4 CRC32 table at %s" % (a.toString(),))
                i += 1
            off += chunk
    return hits


def decompile_function(func, timeout=DECOMP_TIMEOUT):
    try:
        ifc = DecompInterface()
        ifc.openProgram(currentProgram)
        res = ifc.decompileFunction(func, timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted(): return None
        return res.getDecompiledFunction().getC()
    except:
        return None


def detect_rc4_in_decomp(ctext):
    if ctext is None: return (False, False)
    low = ctext.lower()
    ksa = False; prga = False
    if RE_FOR_256.search(low) and (RE_MASK_0xFF.search(low) or RE_KEY_MOD.search(low) or RE_SWAP.search(low)):
        ksa = True
    if RE_PRGA_I.search(low) and (RE_PRGA_J.search(low) or RE_PRGA_OUT.search(low) or ("s[" in low and "^" in low)):
        prga = True
    return (ksa, prga)


def detect_xtea_in_decomp(ctext):
    if ctext is None: return False
    if RE_XTEA_ARX.search(ctext):
        return True
    return False


def detect_prng_in_decomp(ctext):
    tags = []
    if ctext is None: return tags
    low = ctext.lower()
    if RE_PRNG_PM.search(low): tags.append("Park-Miller/Bays-Durham")
    if RE_PRNG_KNUTH.search(low): tags.append("Knuth_subtractive")
    if RE_LCG.search(low): tags.append("LCG")
    return tags

# find functions referencing an address (via references)
def find_functions_referencing(addr):
    funcs = set()
    try:
        refs = refmgr.getReferencesTo(addr)
        for r in refs:
            f = fm.getFunctionContaining(r.getFromAddress())
            if f is not None:
                funcs.add(f)
    except:
        # fallback: scan functions and find instruction strings containing addr text (slow)
        for f in fm.getFunctions(True):
            try:
                for ins in listing.getInstructions(f.getBody(), True):
                    if addr.toString().lower() in ins.toString().lower():
                        funcs.add(f); break
            except:
                pass
    return list(funcs)

# find static key array from decompiled text heuristically
def find_static_key_from_decomp(ctext):
    """Extract possible static key array from decompiled function text."""

    if ctext is None: return None
    low = ctext.lower()
    # look for key[i % n] or key[...] syntax
    m = RE_KEY_MOD.search(low)
    if m:
        name = m.group(1)
        try:
            syms = symtab.getSymbols(name)
            for s in syms:
                a = s.getAddress()
                if a is not None and memory.contains(a):
                    bb = read_bytes(a, KEY_READ_MAX)
                    if bb is not None:
                        return {"name": name, "addr": a, "bytes": bb}
        except:
            pass
    # fallback: find dat_xxx tokens
    dats = re.findall(r'dat_[0-9a-f]{4,}', ctext, re.IGNORECASE)
    for tok in dats:
        try:
            syms = symtab.getSymbols(tok)
            for s in syms:
                a = s.getAddress()
                if a is not None and memory.contains(a):
                    bb = read_bytes(a, KEY_READ_MAX)
                    if bb is not None:
                        return {"name": tok, "addr": a, "bytes": bb}
        except:
            pass
    # weak fallback: search for symbol names 'key' literally
    try:
        syms = symtab.getSymbols("key")
        for s in syms:
            a = s.getAddress()
            if a is not None and memory.contains(a):
                bb = read_bytes(a, KEY_READ_MAX)
                if bb: return {"name": "key", "addr": a, "bytes": bb}
    except:
        pass
    return None

# RC4 KSA emulator
def rc4_ksa_emulate(key_bytes):
    """Emulate RC4 KSA with given key bytes; return S array."""
    keylen = len(key_bytes)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + (key_bytes[i % keylen] & 0xff)) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def compare_emulated_to_table(emuS, table_addr):
    obs = read_bytes(table_addr, 256)
    if obs is None: return False
    for i in range(256):
        if (emuS[i] & 0xff) != (obs[i] & 0xff): return False
    return True


def func_accesses_io(func):
    """Check if function accesses known I/O registers.
    
    Crypto stuff is usually correlated with radio I/O (UCAx/UCBx TX/RXBUF, PORTxOUT).
    """

    hits = []
    try:
        for ins in listing.getInstructions(func.getBody(), True):
            s = ins.toString().lower()
            for name, addr in IO_REGS.items():
                # match hex or name in disasm text
                if name.lower() in s or hex(addr)[2:].lower() in s:
                    hits.append((ins.getAddress(), name))
    except:
        pass
    return hits


def analyze_functions(tables):
    """Scan all functions for crypto/prng patterns."""

    rc4_candidates = []
    xtea_candidates = []
    prng_candidates = []
    verified_rc4 = []
    funcs = fm.getFunctions(True)
    total = 0
    for f in funcs:
        total += 1
        try:
            ctext = decompile_function(f)
            if ctext is None: continue
            # RC4 heuristics
            ksa, prga = detect_rc4_in_decomp(ctext)
            if ksa or prga:
                note(f.getEntryPoint(), BOOKMARK_RC4, "Function", "RC4-like: KSA=%s PRGA=%s" % (str(ksa), str(prga)))
                rc4_candidates.append((f, ctext, ksa, prga))
            # XTEA heuristics
            if detect_xtea_in_decomp(ctext):
                note(f.getEntryPoint(), BOOKMARK_CRYPTO, "Function", "XTEA/TEA-like ARX pattern or delta constant")
                xtea_candidates.append((f, ctext))
            # PRNG heuristics
            prng_tags = detect_prng_in_decomp(ctext)
            if prng_tags:
                note(f.getEntryPoint(), BOOKMARK_PRNG, "Function", "PRNG hints: %s" % (", ".join(prng_tags)))
                prng_candidates.append((f, ctext, prng_tags))
            # correlate with I/O
            io_hits = func_accesses_io(f)
            if io_hits:
                for addr, name in io_hits:
                    note(addr, BOOKMARK_CRYPTO_IO, "I/O", "Access to %s inside function %s" % (name, f.getName()))
                # If function had both RC4 and IO, highlight potential encryption->radio function
                if (ksa or prga):
                    note(f.getEntryPoint(), BOOKMARK_CRYPTO_IO, "Correlation", "Function performs crypto and radio I/O")
        except Exception as e:
            # ignore decompiler errors
            pass

    # Attempt key extraction + verification for RC4 candidates
    for (f, ctext, ksa_flag, prga_flag) in rc4_candidates:
        if not ksa_flag: continue
        # find possible tables referenced in decomp
        dat_tokens = re.findall(r'dat_[0-9a-f]{4,}', ctext, re.IGNORECASE)
        symbol_tokens = re.findall(r'([A-Za-z_0-9]+)\s*\[', ctext)
        candidate_tables = []
        # resolve DAT tokens
        for tok in dat_tokens:
            try:
                syms = symtab.getSymbols(tok)
                for s in syms:
                    a = s.getAddress()
                    if a is not None:
                        bb = read_bytes(a, 256)
                        if bb is not None and is_256_permutation(bb):
                            candidate_tables.append(a)
            except:
                pass
        # resolve symbol tokens
        for tok in symbol_tokens:
            try:
                syms = symtab.getSymbols(tok)
                for s in syms:
                    a = s.getAddress()
                    if a is not None:
                        bb = read_bytes(a, 256)
                        if bb is not None and is_256_permutation(bb):
                            candidate_tables.append(a)
            except:
                pass
        # xref-based matching: see if any global table refs come from this function
        for t in tables:
            try:
                refs = refmgr.getReferencesTo(t)
                for r in refs:
                    if f.getBody().contains(r.getFromAddress()):
                        candidate_tables.append(t)
            except:
                pass
        # dedupe
        uniq = []
        for t in candidate_tables:
            if t not in uniq: uniq.append(t)
        candidate_tables = uniq

        # try find static key and emulate
        keyinfo = find_static_key_from_decomp(ctext)
        if keyinfo is not None:
            note(f.getEntryPoint(), BOOKMARK_RC4, "Key", "Possible static key array '%s' at %s (first bytes: %s)" %
                 (keyinfo.get("name"), keyinfo.get("addr").toString(), " ".join(["%02x" % (b,) for b in keyinfo.get("bytes")])))
            # try candidate key lengths
            kb = keyinfo.get("bytes")
            max_try = min(len(kb), KEY_READ_MAX)
            for taddr in candidate_tables:
                verified = False
                for klen in range(1, max_try+1):
                    keyb = [ (kb[i] & 0xff) for i in range(klen) ]
                    emuS = rc4_ksa_emulate(keyb)
                    if compare_emulated_to_table(emuS, taddr):
                        note(taddr, BOOKMARK_RC4, "Verified", "RC4 KSA verified for table with key @ %s length %d" % (keyinfo.get("addr").toString(), klen))
                        verified_rc4 = {"function": f, "table": taddr, "key_addr": keyinfo.get("addr"), "key_len": klen}
                        verified = True
                        break
                if not verified:
                    note(taddr, BOOKMARK_RC4, "Verify", "Tried emulating KSA with static key at %s; no match" % (keyinfo.get("addr").toString(),))
        else:
            # no static key found: still bookmark candidate tables
            for taddr in candidate_tables:
                note(taddr, BOOKMARK_RC4, "Candidate", "KSA-like function %s references this table; no static key found" % (f.getName(),))

    # done
    return {
        "rc4_candidates_count": len(rc4_candidates),
        "xtea_count": len(xtea_candidates),
        "prng_count": len(prng_candidates)
    }

def scan_constants_and_prngs():
    const_hits = []
    blocks = memory.getBlocks()

    # Always store integers as keys, names as values
    needles = {
        PM_IA:         "Park-Miller IA",
        PM_IM:         "Park-Miller IM",
        PM_IQ:         "Park-Miller IQ",
        PM_IR:         "Park-Miller IR",
        KNUTH_MBIG:    "Knuth MBIG",
        KNUTH_MSEED:   "Knuth MSEED",
        TEA_DELTA:     "TEA delta",
        TEA_SUM32:     "TEA sum32",
        CRC32_POLY:    "CRC32 poly"
    }

    # Build little-endian byte patterns
    le_map = {}
    for const_val, const_name in needles.items():
        if not isinstance(const_val, (int, long)):
            continue
        b = bytearray([
            const_val        & 0xff,
            (const_val >> 8) & 0xff,
            (const_val >> 16)& 0xff,
            (const_val >> 24)& 0xff
        ])
        le_map[bytes(b)] = (const_val, const_name)

    for blk in blocks:
        if not blk.isInitialized():
            continue
        start = blk.getStart()
        size  = blk.getSize()
        off   = 0
        while off < size:
            chunk = min(MAX_CHUNK, size - off)
            base  = start.add(off)
            bb    = read_bytes(base, chunk)
            if bb is None:
                off += chunk
                continue

            for i in range(0, len(bb) - 4 + 1):
                key = bytes(bb[i:i+4])
                if key in le_map:
                    (val, name) = le_map[key]
                    addr = base.add(i)
                    note(addr, BOOKMARK_PRNG, "Const", "Found %s (%s)" % (hex(val), name))
                    const_hits.append((addr, val, name))
            off += chunk

    return {"consts": const_hits}

# I/O correlation scan (global)
def scan_io_accesses():
    io_hits = []
    for f in fm.getFunctions(True):
        try:
            for ins in listing.getInstructions(f.getBody(), True):
                s = ins.toString().lower()
                for name, addr in IO_REGS.items():
                    if name.lower() in s or hex(addr)[2:].lower() in s:
                        note(ins.getAddress(), BOOKMARK_CRYPTO_IO, "I/O", "Access to %s in function %s" % (name, f.getName()))
                        io_hits.append((f, name, ins.getAddress()))
        except:
            pass
    return io_hits

# main orchestrator
def main():
    start = time.time()
    note(currentProgram.getMinAddress(), BOOKMARK_CRYPTO, "Info", "Mega crypto+PRNG scan started")
    # data scans
    tables = find_256_tables()
    aes_hits = find_aes_rcon_and_sboxes()
    crc_hits = find_crc32_tables()
    # constants & prng
    prng_res = scan_constants_and_prngs()
    # function scans and correlation
    func_summary = analyze_functions(tables)
    io_hits = scan_io_accesses()
    # summary
    elapsed = time.time() - start
    summary_lines = []
    summary_lines.append("Mega scan complete in %.2f s" % (elapsed,))
    summary_lines.append("256-tables found: %d" % (len(tables),))
    summary_lines.append("AES/Rcon hits: %d" % (len(aes_hits),))
    summary_lines.append("CRC-like hits: %d" % (len(crc_hits),))
    summary_lines.append("PRNG consts found: %d" % (len(prng_res.get("consts", [])),))
    summary_lines.append("PRNG tables (symbol hits): %d" % (len(prng_res.get("tables", [])),))
    summary_lines.append("RC4 candidates (functions): %d" % (func_summary.get("rc4_candidates_count", 0),))
    summary_lines.append("XTEA-like functions: %d" % (func_summary.get("xtea_count", 0),))
    summary_lines.append("PRNG-like functions: %d" % (func_summary.get("prng_count", 0),))
    summary_lines.append("I/O hits (functions accessing TX/RX/PORT): %d" % (len(io_hits),))
    # print and popup
    print("==== MegaCryptoDetect Summary ====")
    for l in summary_lines:
        print(l)
    ta = JTextArea("\n".join(summary_lines), 16, 80)
    ta.setEditable(False)
    sp = JScrollPane(ta)
    JOptionPane.showMessageDialog(None, sp, "MegaCryptoDetect Summary", JOptionPane.PLAIN_MESSAGE)

if __name__ == "__main__":
    main()