# -*- coding: utf-8 -*-
# DirtyCrypto.py
#
# - RC4 (256-byte permutation detection, KSA/PRGA heuristics, key extraction, KSA emulation verification)
# - AES S-box / invS-box / Rcon detection
# - XTEA/TEA heuristics (constants and ARX patterns)
# - CRC table heuristics
# - PRNG detection (Knuth subtractive, NR ran1, RANDU, LCG)
# - Correlation with radio I/O (UCAx/UCBx TX/RXBUF, P1OUT..P4OUT)
# - Adds Bookmarks and Plate comments (no renaming/modification)

#@category DataCrypto
#@author J. DeFrancesco



from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.mem import MemoryAccessException
from javax.swing import JOptionPane, JScrollPane, JTextArea

import re, time

# ---------- Configuration ----------
BOOKMARK_CRYPTO     = "CRYPTO"
BOOKMARK_RC4        = "CRYPTO_RC4"
BOOKMARK_PRNG       = "CRYPTO_PRNG"
BOOKMARK_CRYPTO_IO  = "CRYPTO_IO"
BOOKMARK_TABLE      = "CRYPTO_TABLE"
BOOKMARK_XTEA       = "CRYPTO_XTEA"

MAX_CHUNK = 0x10000
DECOMP_TIMEOUT = 6
KEY_READ_MAX = 64

# constants and signatures
AES_SBOX_HEAD = [0x63,0x7c,0x77,0x7b]
AES_INV_HEAD  = [0x52,0x09,0x6a,0xd5]
AES_RCON_SEQ  = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
TEA_DELTA     = 0x9E3779B9
TEA_SUM32     = 0xC6EF3720
CRC32_POLY    = 0xEDB88320

# PRNG constants
PM_IA = 16807
PM_IM = 2147483647
PM_IQ = 127773
PM_IR = 2836
KNUTH_MBIG  = 1000000000
KNUTH_MSEED = 161803398

# I/O register hints (MSP430F5438 common)
IO_REGS = {
    "UCA0RXBUF": 0x05C6, "UCA0TXBUF": 0x05C7,
    "UCB0RXBUF": 0x05DD, "UCB0TXBUF": 0x05DE,
    "UCB1RXBUF": 0x05ED, "UCB1TXBUF": 0x05EE,
    "P1OUT": 0x0202, "P2OUT": 0x0203, "P3OUT": 0x0222, "P4OUT": 0x0223
}

# regex heuristics (decompiler text)
RE_FOR_256    = re.compile(r'\bfor\b[^;]*;\s*i\s*<\s*256\b', re.IGNORECASE)
RE_MASK_0xFF  = re.compile(r'&\s*0x?ff\b', re.IGNORECASE)
RE_KEY_MOD    = re.compile(r'([A-Za-z_0-9]+)\s*\[\s*i\s*%\s*([0-9A-Za-z_]+)\s*\]', re.IGNORECASE)
RE_SWAP       = re.compile(r'swap\s*\(|tmp\s*=.*s\[', re.IGNORECASE)
RE_PRGA_I     = re.compile(r'i\s*=\s*\(?i\s*\+\s*1\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_J     = re.compile(r'j\s*=\s*\(?j\s*\+\s*s\[\s*i\s*\]\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_OUT   = re.compile(r'\^\s*s\[\s*\(s\[.*i.*\]\s*\+\s*s\[.*j.*\]\s*\)\s*&\s*0x?ff', re.IGNORECASE)
RE_XTEA_ARX   = re.compile(r'<<\s*4|>>\s*5|0x9e3779b9|0xc6ef3720', re.IGNORECASE)
RE_PRNG_PM    = re.compile(r'16807|127773|2836|0x41a7|0x1f31d|0x0b14', re.IGNORECASE)
RE_PRNG_KNUTH = re.compile(r'161803398|1000000000|55|24', re.IGNORECASE)
RE_LCG        = re.compile(r'1103515245|12345|65539|0x41c64e6d|0x3039|0x00010003', re.IGNORECASE)

# Ghidra objects
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
bkm = currentProgram.getBookmarkManager()
fm = currentProgram.getFunctionManager()
symtab = currentProgram.getSymbolTable()
refmgr = currentProgram.getReferenceManager()

def note(addr, category, kind, msg):
    try:
        bkm.setBookmark(addr, category, kind, msg)
    except:
        pass
    try:
        listing.setComment(addr, CodeUnit.PLATE_COMMENT, "[%s] %s" % (category, msg))
    except:
        pass
    print("%s | %s @ %s : %s" % (category, kind, addr.toString(), msg))

def read_bytes(addr, n):
    try:
        bb = bytearray(n)
        memory.getBytes(addr, bb)
        return bb
    except:
        return None

def is_256_permutation(bb, off=0):
    if bb is None or off+256 > len(bb): return False
    seen = [False]*256
    for i in range(256):
        v = bb[off+i]
        if seen[v]:
            return False
        seen[v] = True
    return True

def decompile_function(func, timeout=DECOMP_TIMEOUT):
    try:
        ifc = DecompInterface()
        ifc.openProgram(currentProgram)
        res = ifc.decompileFunction(func, timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            return None
        return res.getDecompiledFunction().getC()
    except:
        return None

def find_256_tables():
    """find256_tables attempts to look for potential S-Box like data
    
    RC4 utilizes 256 S-box data. We scan through chunks and
    check if any boxes contain permutations of bytes i.e no duplicate
    bytes are found within a block which is necessary for RC4.

    This runs in O(N^2) so it could take a bit!
    """
    results = []
    for blk in memory.getBlocks():
        if not blk.isInitialized():
            continue

        start = blk.getStart()
        size = blk.getSize()
        off = 0
        while off < size:
            chunk = MAX_CHUNK if (size-off) > MAX_CHUNK else (size-off)
            base = start.add(off)
            bb = read_bytes(base, chunk)
            if bb is None:
                off += chunk
                continue

            i = 0
            L = len(bb)

            while i + 256 <= L:
                if is_256_permutation(bb, i):
                    addr = base.add(i)
                    results.append(addr)
                    note(addr, BOOKMARK_TABLE, "RC4_SBOX", "256-byte permutation (S[] candidate)")
                    i += 256
                    continue
                i += 1
            off += chunk
    return results

def find_aes_rcon_and_sboxes():
    """Find AES S-BOX and other structures."""

    hits = []
    for blk in memory.getBlocks():
        if not blk.isInitialized(): continue
        start = blk.getStart(); size = blk.getSize(); off = 0
        while off < size:
            chunk = MAX_CHUNK if (size-off) > MAX_CHUNK else (size-off)
            base = start.add(off)
            bb = read_bytes(base, chunk)
            if bb is None:
                off += chunk; continue
            L = len(bb)
            for i in range(0, L-4+1):
                if bb[i:i+4] == bytearray(AES_SBOX_HEAD):
                    a = base.add(i); hits.append((a,"AES_SBOX")); note(a, BOOKMARK_TABLE, "AES", "AES S-box header")
                if bb[i:i+4] == bytearray(AES_INV_HEAD):
                    a = base.add(i); hits.append((a,"AES_INV")); note(a, BOOKMARK_TABLE, "AES", "AES inverse S-box header")
                if i + len(AES_RCON_SEQ) <= L:
                    ok = True
                    for j in range(len(AES_RCON_SEQ)):
                        if bb[i+j] != AES_RCON_SEQ[j]:
                            ok = False; break
                    if ok:
                        a = base.add(i); hits.append((a,"AES_RCON")); note(a, BOOKMARK_TABLE, "AES", "AES Rcon sequence")
            off += chunk
    return hits

def mark_rc4_instr_patterns(func):
    """
    Scan function instructions and add bookmarks on instructions that match RC4-like patterns:
    - CMP #0x100 or CMP #256
    - AND #0xFF
    - MOV.B with indexed addressing (array access)
    - ADD.B reading from memory (S[i] or key bytes) into a register (j update)
    - Swap-like sequences: sequence of MOV.B that move between memory and registers
    """
    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    hits = 0
    # sliding window for swap detection
    recent_movs = []
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        # CMP #0x100 or CMP #256
        if "cmp" in s and ("#0x100" in s or "#256" in s):
            note(a, BOOKMARK_RC4, "RC4_CMP", "Loop bound CMP #256 (possible KSA loop bound)")
            hits += 1
        # AND #0xFF
        if ("and" in s or "and.b" in s) and ("#0xff" in s or "#255" in s):
            note(a, BOOKMARK_RC4, "RC4_AND", "AND #0xFF (index modulo byte mask)")
            hits += 1
        # MOV.B with parentheses (indexed memory)
        if "mov.b" in s and ("(" in s and ")" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "RC4_INDEXED", "MOV.B indexed memory (S[i] or key lookup)")
            hits += 1
            recent_movs.append((a, s))
            if len(recent_movs) > 6:
                recent_movs.pop(0)
        # ADD.B reading from memory (j += S[i] or j += key[i%len])
        if ("add.b" in s or "add" in s) and ("(" in s and ")" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "RC4_ADD_MEM", "ADD from memory (possible j += S[i] or j += key)")
            hits += 1
        # XOR pattern used when generating keystream (less common as it may use MOV)
        if ("xor" in s or "xor.b" in s) and ("(" in s and ")" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "RC4_XOR", "XOR with memory indexed (possible keystream output)")
            hits += 1
        # detect swap sequence heuristically
        if len(recent_movs) >= 3:
            # check variety of registers / memrefs to suspect swap
            memcount = sum(1 for (_,txt) in recent_movs[-3:] if "(" in txt or "@r" in txt)
            regs = set()
            for (_,txt) in recent_movs[-3:]:
                for tok in re.split(r'[\s,()]+', txt):
                    if tok.startswith("r") and tok[1:].isdigit():
                        regs.add(tok)
            if memcount >= 2 and len(regs) >= 2:
                # bookmark each mov in the window as possible swap
                for (aa,txt) in recent_movs[-3:]:
                    note(aa, BOOKMARK_RC4, "RC4_SWAP", "Swap-like MOV.B sequence (part of S[i]<->S[j])")
                    hits += 1
                recent_movs = []
    return hits

def mark_xtea_instr_patterns(func):
    """
    Bookmark instructions referencing TEA/XTEA delta constants and ARX operations.
    - Immediate constant 0x9E3779B9 or 0xC6EF3720 (seen as decimal too)
    - ADD/PLUS and XOR sequences
    """
    hits = 0
    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        if "0x9e3779b9" in s or "0xc6ef3720" in s or "2654435769" in s or "3337565984" in s:
            note(a, BOOKMARK_XTEA, "XTEA_CONST", "TEA/XTEA delta constant referenced")
            hits += 1
        # ARX ops: add, xor, rol/ror shifts often used in TEA variants
        if ("add" in s or "xor" in s or "rol" in s or "ror" in s or "lsl" in s or "lsr" in s) and ("r" in s):
            # simple heuristic: presence of both add and xor nearby will be more convincing
            note(a, BOOKMARK_XTEA, "XTEA_ARX", "ARX-like op (add/xor/rotate) — possible TEA/XTEA")
            hits += 1
    return hits

def mark_prng_instr_patterns(func):
    """Bookmark instructions containing PRNG constants (Park-Miller, Knuth).
    """
    hits = 0
    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        # Park-Miller constants used in LCG RNG
        if "16807" in s or "127773" in s or "2836" in s or "0x41a7" in s:
            note(a, BOOKMARK_PRNG, "PRNG_PM", "Park-Miller related constant used")
            hits += 1
        # Knuth constants for subtractive random number generator
        if "161803398" in s or "1000000000" in s or "0x5f5e100" in s:
            note(a, BOOKMARK_PRNG, "PRNG_KNUTH", "Knuth subtractive related constant used")
            hits += 1
        # LCG hints
        if "1103515245" in s or "0x41c64e6d" in s:
            note(a, BOOKMARK_PRNG, "PRNG_LCG", "LCG-like constant referenced")
            hits += 1
    return hits

def detect_rc4_in_decomp(ctext):
    """Brittle attempt to find rc4 heruristics in C decompilation"""

    if ctext is None: 
        return (False, False)
    low = ctext.lower()
    ksa = RE_FOR_256.search(low) and (RE_MASK_0xFF.search(low) or RE_KEY_MOD.search(low) or RE_SWAP.search(low))
    prga = RE_PRGA_I.search(low) and (RE_PRGA_J.search(low) or RE_PRGA_OUT.search(low) or ("s[" in low and "^" in low))
    return (bool(ksa), bool(prga))

def find_static_key_from_decomp(ctext):
    """Attempt to locate a static key in decompilation near potential crypto funcs."""
    if ctext is None: return None
    low = ctext.lower()
    m = RE_KEY_MOD.search(low)
    if m:
        name = m.group(1)
        try:
            for s in symtab.getSymbols(name):
                a = s.getAddress()
                if a and memory.contains(a):
                    bb = read_bytes(a, KEY_READ_MAX)
                    if bb is not None:
                        return {"name": name, "addr": a, "bytes": bb}
        except:
            pass
    # dat_ tokens
    for tok in re.findall(r'dat_[0-9a-f]{4,}', ctext, re.IGNORECASE):
        try:
            for s in symtab.getSymbols(tok):
                a = s.getAddress()
                if a and memory.contains(a):
                    bb = read_bytes(a, KEY_READ_MAX)
                    if bb is not None:
                        return {"name": tok, "addr": a, "bytes": bb}
        except:
            pass
    return None

def rc4_ksa_emulate(key_bytes):
    """emulate KSA rc4"""

    # TODO: Will be useful to compare table to tables found in bin
    S = list(range(256)); j = 0; klen = len(key_bytes)
    for i in range(256):
        j = (j + S[i] + (key_bytes[i % klen] & 0xff)) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def compare_emulated_to_table(emuS, table_addr):
    obs = read_bytes(table_addr, 256)
    if obs is None: return False
    for i in range(256):
        if (emuS[i] & 0xff) != (obs[i] & 0xff): return False
    return True

def analyze_functions_marking(tables):
    rc4_c_count = 0
    xtea_count = 0
    prng_func_count = 0
    for f in fm.getFunctions(True):
        try:
            ctext = decompile_function(f)
            if ctext:
                ksa, prga = detect_rc4_in_decomp(ctext)
                if ksa or prga:
                    note(f.getEntryPoint(), BOOKMARK_RC4, "RC4_C", "RC4-like (decomp): KSA=%s PRGA=%s" % (str(ksa), str(prga)))
                    rc4_c_count += 1
                # Mark instructions in the function that match RC4 heuristics (more precise)
                mark_rc4_instr_patterns(f)
                # XTEA by decomp heuristic
                if RE_XTEA_ARX.search(ctext):
                    note(f.getEntryPoint(), BOOKMARK_XTEA, "XTEA_FUNC", "XTEA/TEA-like (decompiler pattern)")
                    xtea_count += 1
                # Decomp PRNG hints
                if RE_PRNG_PM.search(ctext) or RE_PRNG_KNUTH.search(ctext) or RE_LCG.search(ctext):
                    note(f.getEntryPoint(), BOOKMARK_PRNG, "PRNG_FUNC", "PRNG-like pattern in decompiler")
                    prng_func_count += 1
            # Independent instruction-level passes (always run)
            mark_xtea_instr_patterns(f)
            mark_prng_instr_patterns(f)
        except:
            pass
    return {"rc4_c": rc4_c_count, "xtea": xtea_count, "prng_funcs": prng_func_count}


def detect_rc4_asm_in_function(func):
    """Look for rc4 heuristic instructions."""

    score = 0
    flags = set()
    pcs = []
    recent_movs = []
    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return {"score":0,"flags":flags,"pcs":pcs}
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()

        # CMP #0x100
        if "cmp" in s and ("#0x100" in s or "#256" in s):
            score += 3; flags.add("cmp_256"); pcs.append(a)
            note(a, BOOKMARK_RC4, "RC4_CMP", "CMP #256 (KSA bound?)")

        # AND #0xFF
        if ("and" in s or "and.b" in s) and ("#0xff" in s or "#255" in s):
            score += 2; flags.add("and_ff"); pcs.append(a)
            note(a, BOOKMARK_RC4, "RC4_AND", "AND #0xFF")

        # INC or ADD #1
        if ("inc" in s or ("add" in s and "#1" in s)):
            score += 1; pcs.append(a)

        # Indexed MOV.B (S[i] or key access)
        if "mov.b" in s and ("(" in s and ")" in s or "@r" in s):
            score += 2; flags.add("mov_index"); pcs.append(a)
            recent_movs.append((a,s))
            if len(recent_movs)>6: recent_movs.pop(0)

        # ADD.B from memory (j += S[i] or key)
        if ("add.b" in s or "add" in s) and ("(" in s and ")" in s or "@r" in s):
            score += 2; flags.add("add_mem"); pcs.append(a)

        # swap-like mov triple detection
        if len(recent_movs) >= 3:
            memcount = sum(1 for (_,txt) in recent_movs[-3:] if "(" in txt or "@r" in txt)
            regs = set()
            for (_,txt) in recent_movs[-3:]:
                for tok in re.split(r'[\s,()]+', txt):
                    if tok.startswith("r") and tok[1:].isdigit():
                        regs.add(tok)
            if memcount >= 2 and len(regs) >= 2:
                score += 3; flags.add("swap_seq")
                for (aa,txt) in recent_movs[-3:]:
                    note(aa, BOOKMARK_RC4, "RC4_SWAP", "Swap-like MOV.B (part of S[i]<->S[j])")
                recent_movs = []

    return {"score": score, "flags": flags, "pcs": pcs}

def rc4_asm_scan_and_mark():
    """Mark anything with score over 5 for now."""

    total=0
    for f in fm.getFunctions(True):
        try:
            res = detect_rc4_asm_in_function(f)
            if res["score"] >= 5:
                ep = f.getEntryPoint()
                if "swap_seq" in res["flags"] or "cmp_256" in res["flags"]:
                    note(ep, BOOKMARK_RC4, "RC4_ASM_FUNC", "ASM RC4-like pattern (score=%s) flags=%s" % (str(res["score"]), ", ".join(res["flags"])))
                    total += 1
        except:
            pass
    return total

def scan_constants_and_prngs_and_mark():
    """Looks for constants associatied with certain ciphers and rng"""

    results = []
    needles = {
        PM_IA: "Park-Miller IA", PM_IM: "Park-Miller IM",
        PM_IQ: "Park-Miller IQ", PM_IR: "Park-Miller IR",
        KNUTH_MBIG: "Knuth MBIG", KNUTH_MSEED: "Knuth MSEED",
        TEA_DELTA: "TEA delta", TEA_SUM32: "TEA sum32",
        CRC32_POLY: "CRC32 poly"
    }
    # Build 4-byte little endian patterns
    le_map = {}
    int_types = (int,)

    for const_val, name in needles.items():
        if not isinstance(const_val, int_types):
            continue
        b = bytearray([(const_val & 0xff), ((const_val>>8)&0xff), ((const_val>>16)&0xff), ((const_val>>24)&0xff)])
        le_map[bytes(b)] = (const_val, name)

    # Scan initialized blocks
    for blk in memory.getBlocks():
        if not blk.isInitialized(): continue
        base = blk.getStart(); size = blk.getSize(); off=0
        while off < size:
            chunk = min(MAX_CHUNK, size-off)
            baddr = base.add(off)
            bb = read_bytes(baddr, chunk)
            if bb is None: off += chunk; continue
            for i in range(0, len(bb)-4+1):
                try:
                    k = bytes(bb[i:i+4])
                except:
                    k = str(bytearray(bb[i:i+4]))
                if k in le_map:
                    (val, name) = le_map[k]
                    addr = baddr.add(i)
                    note(addr, BOOKMARK_PRNG, "CONST", "Constant 0x%08x (%s) found in data" % (val, name))
                    results.append((addr, val, name))
            off += chunk
    
    # Instruction-level PRNG constant bookmarks too..
    prng_instr_hits = 0
    for f in fm.getFunctions(True):
        try:
            for ins in listing.getInstructions(f.getBody(), True):
                s = ins.toString().lower()
                a = ins.getAddress()
                if "16807" in s or "127773" in s or "2836" in s or "161803398" in s or "1000000000" in s:
                    note(a, BOOKMARK_PRNG, "CONST_USE", "PRNG constant used in instruction: %s" % s)
                    prng_instr_hits += 1
        except:
            pass

    return {"data": results, "instr_hits": prng_instr_hits}


def func_accesses_io(func):
    """Look for IO serial access and mark it."""

    hits=[]
    try:
        for ins in listing.getInstructions(func.getBody(), True):
            s = ins.toString().lower()
            for name, addr in IO_REGS.items():
                if name.lower() in s or hex(addr)[2:].lower() in s:
                    note(ins.getAddress(), BOOKMARK_CRYPTO_IO, "I/O", "Access to %s in function %s" % (name, func.getName()))
                    hits.append((ins.getAddress(), name))
    except:
        pass
    return hits

def find_crc16_constants():
    """
    Scan memory for CRC-16 constants/polynomials in little endian.
    Common ones:
      - CRC16-IBM:    0x8005  -> bytes: 05 80
      - CRC16-CCITT:  0x1021  -> bytes: 21 10
      - CRC16-MODBUS: 0xA001  -> bytes: 01 A0
    """
    CRC16_POLYS = {
        "\x05\x80": "CRC16_IBM (0x8005)",
        "\x21\x10": "CRC16_CCITT (0x1021)",
        "\x01\xA0": "CRC16_MODBUS (0xA001)"
    }

    hits = []
    for blk in memory.getBlocks():
        if not blk.isInitialized():
            continue
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

            for i in range(0, len(bb) - 2 + 1):
                pair = bb[i:i+2]
                for k in CRC16_POLYS:
                    if pair == bytearray(k):
                        addr = base.add(i)
                        note(addr, BOOKMARK_TABLE, "CRC16", "CRC-16 polynomial found: " + CRC16_POLYS[k])
                        hits.append(addr)

            off += chunk

    return hits


def main():
    
    print("==== [D430] Crypto Scanner =====")
    start = time.time()
    note(currentProgram.getMinAddress(), BOOKMARK_CRYPTO, "Info", "D430 Scanner mark.")

    # Data scans
    print("[D430] Attempting to find potential S-Box tables")
    tables = find_256_tables()
    aes_hits = find_aes_rcon_and_sboxes()
    crc16_hits = find_crc16_constants()

    # Prng constants scan..
    print("[D430] Scanning for constants")
    prng_res = scan_constants_and_prngs_and_mark()

    # Function-level decomp marking.
    func_summary = analyze_functions_marking(tables)

    # ASM-only RC4 detection (marks instrs in functions too)
    print("[D430] Scanning and marking possible rc4 instructions.")
    rc4_asm_hits = rc4_asm_scan_and_mark()

    # USCI scan
    usci_count = 0
    mods = {}  # keep minimal - collect symbols if needed

    # Quick scan for I/O accesses and mark them..
    io_hits_total = 0
    for f in fm.getFunctions(True):
        hits = func_accesses_io(f)
        if hits:
            io_hits_total += len(hits)
            usci_count += 1

    elapsed = time.time() - start
    lines = []
    lines.append("D430 scan complete in %.2f s" % (elapsed,))
    lines.append("CRC16 constants found: %d" % (len(crc16_hits),))
    lines.append("RC4 S[] tables: %d" % (len(tables),))
    lines.append("AES/Rcon hits: %d" % (len(aes_hits),))
    lines.append("PRNG constant data hits: %d" % (len(prng_res.get("data", [])),))
    lines.append("PRNG instruction hits: %d" % (prng_res.get("instr_hits", 0),))
    lines.append("RC4 (decompiler) functions: %d" % (func_summary.get("rc4_c",0),))
    lines.append("RC4 (ASM instr) detections (functions): %d" % rc4_asm_hits)
    lines.append("XTEA-like functions: %d" % (func_summary.get("xtea",0),))
    lines.append("Functions with USCI I/O hits: %d (IO bookmarks: %d)" % (usci_count, io_hits_total))

    print("==== D430 Crypto Summary ====")
    for l in lines: 
        print(l)

    ta = JTextArea("\n".join(lines), 16, 80); ta.setEditable(False)
    JOptionPane.showMessageDialog(None, JScrollPane(ta), "D430 Crypto Summary", JOptionPane.PLAIN_MESSAGE)

    print("==== D430 Crypto Finished! ====")

if __name__ == "__main__":
    main()