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
#
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
BOOKMARK_MOD        = "CRYPTO_MOD"

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

# less brittle RC4-like variant hints (VMPC/RC4A)
RE_INDEXED_ARRAY = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\[', re.IGNORECASE)
RE_ARRAY_XOR     = re.compile(r'\]\s*\^\s*[A-Za-z_][A-Za-z0-9_]*\s*\[', re.IGNORECASE)
RE_NESTED_ARRAY  = re.compile(r'\[[^\]]*\[[^\]]*\]', re.IGNORECASE)

# MSP430 specific asm regexes for runtime S detection and modulo
RE_MOV_IMM_TO_REG = re.compile(r'\bmov(\.w|\s)\s*#(0x[0-9a-f]+|\d+)\s*,\s*(r\d+)', re.IGNORECASE)
RE_MOVB_STORE_IDX = re.compile(r'\bmov\.b\s+\S+,\s*([+-]?\d+)\((r\d+)\)', re.IGNORECASE)
RE_MOVW_STORE_IDX = re.compile(r'\bmov(\.w|\s)\s+\S+,\s*([+-]?\d+)\((r\d+)\)', re.IGNORECASE)
RE_CMP_256        = re.compile(r'\bcmp\b.*(#0x100|#256)', re.IGNORECASE)

RE_AND_IMM        = re.compile(r'\band(\.b|\.w)?\s+#(0x[0-9a-f]+|\d+)\s*,', re.IGNORECASE)
RE_SUB_IMM_REG    = re.compile(r'\bsub(\.b|\.w)?\s+#(0x[0-9a-f]+|\d+)\s*,\s*(r\d+)', re.IGNORECASE)
RE_CMP_IMM_REG    = re.compile(r'\bcmp(\.b|\.w)?\s+#(0x[0-9a-f]+|\d+)\s*,\s*(r\d+)', re.IGNORECASE)
RE_CALL_DIV       = re.compile(r'\bcall\b.*__(div|divu|mod|rem)', re.IGNORECASE)
RE_SHIFT          = re.compile(r'\brr[ac]|rla|rlc', re.IGNORECASE)

# Ghidra objects
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
bkm = currentProgram.getBookmarkManager()
fm = currentProgram.getFunctionManager()
symtab = currentProgram.getSymbolTable()
refmgr = currentProgram.getReferenceManager()

def note(addr, category, kind, msg):
    """
    Create a bookmark and plate comment at the given address, and print a line.

    :param addr: Address to annotate
    :type addr: Address
    :param category: Bookmark category string
    :type category: str
    :param kind: Bookmark type string
    :type kind: str
    :param msg: Message text
    :type msg: str
    :return: None
    :rtype: None
    """

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
    """
    Read n bytes from memory starting at addr.

    :param addr: Start address
    :type addr: Address
    :param n: Number of bytes to read
    :type n: int
    :return: Bytearray of data, or None on failure
    :rtype: bytearray
    """

    try:
        bb = bytearray(n)
        memory.getBytes(addr, bb)
        return bb
    except:
        return None

def _perm_check_bytes(bb, off):
    """
    Check if 256 bytes at offset form a permutation of 0..255.

    :param bb: Buffer to inspect
    :type bb: bytearray
    :param off: Offset into buffer
    :type off: int
    :return: True if permutation
    :rtype: bool
    """

    seen = [False]*256
    for i in range(256):
        v = bb[off+i]
        if v < 0:
            v = v & 0xff
        if seen[v]:
            return False
        seen[v] = True
    return True

def _perm_check_words_lowbyte(bb, off):
    """
    Check if 512 bytes at offset represent 256 words with constant high byte and unique low bytes.

    :param bb: Buffer to inspect
    :type bb: bytearray
    :param off: Offset into buffer
    :type off: int
    :return: True if low bytes form permutation and high bytes constant
    :rtype: bool
    """

    seen = [False]*256
    high = None
    for i in range(256):
        lo = bb[off+2*i]
        hi = bb[off+2*i+1]
        if lo < 0: lo &= 0xff
        if hi < 0: hi &= 0xff
        if high is None:
            high = hi
        else:
            if hi != high:
                return False
        if seen[lo]:
            return False
        seen[lo] = True
    return True

def _identity_check_bytes(bb, off):
    """
    Check for identity sequence 00..FF at offset.

    :param bb: Buffer to inspect
    :type bb: bytearray
    :param off: Offset into buffer
    :type off: int
    :return: True if identity
    :rtype: bool
    """

    for i in range(256):
        v = bb[off+i]
        if v < 0: v &= 0xff
        if v != (i & 0xff):
            return False
    return True

def _identity_check_words(bb, off):
    """
    Check for identity word table 0000, 0100, ..., FF00.

    :param bb: Buffer to inspect
    :type bb: bytearray
    :param off: Offset into buffer
    :type off: int
    :return: True if identity words
    :rtype: bool
    """

    for i in range(256):
        lo = bb[off+2*i]
        hi = bb[off+2*i+1]
        if lo < 0: lo &= 0xff
        if hi < 0: hi &= 0xff
        if lo != (i & 0xff) or hi != 0x00:
            return False
    return True

def is_256_permutation(bb, off=0):
    """
    Backward-compatible byte permutation check for 0..255.

    :param bb: Buffer to inspect
    :type bb: bytearray
    :param off: Offset into buffer
    :type off: int
    :return: True if permutation
    :rtype: bool
    """

    if bb is None or off+256 > len(bb): return False
    return _perm_check_bytes(bb, off)

def decompile_function(func, timeout=DECOMP_TIMEOUT):
    """
    Decompile a function and return the recovered C as a string.

    :param func: Function to decompile
    :type func: ghidra.program.model.listing.Function
    :param timeout: Timeout seconds
    :type timeout: int
    :return: Decompiled C text or None
    :rtype: str
    """

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
    """
    Scan initialized memory for RC4-like tables:
      - 256-byte permutation (any order)
      - 256-byte identity sequence 00..FF
      - 512-byte word table where low bytes form permutation and high bytes constant
      - 512-byte identity word table 0000..FF00

    :return: List of addresses of candidate tables
    :rtype: list
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
            L = len(bb)

            i = 0
            while i + 256 <= L:
                if _perm_check_bytes(bb, i) or _identity_check_bytes(bb, i):
                    addr = base.add(i)
                    results.append(addr)
                    note(addr, BOOKMARK_TABLE, "RC4_SBOX", "256-byte table (perm or identity) candidate")
                    i += 256
                    continue
                i += 1

            j = 0
            while j + 512 <= L:
                if _perm_check_words_lowbyte(bb, j) or _identity_check_words(bb, j):
                    addrw = base.add(j)
                    results.append(addrw)
                    note(addrw, BOOKMARK_TABLE, "RC4_SBOX16", "512-byte word table (low-byte perm or identity) candidate")
                    j += 512
                    continue
                j += 2
            off += chunk
    return results

def find_aes_rcon_and_sboxes():
    """
    Find AES S-box, inverse S-box, and Rcon sequences.

    :return: List of hits with type tags
    :rtype: list
    """

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
    Bookmark assembly instructions that resemble RC4 KSA or PRGA.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: Hit count
    :rtype: int
    """

    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    hits = 0
    recent_movs = []
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        if "cmp" in s and ("#0x100" in s or "#256" in s):
            note(a, BOOKMARK_RC4, "RC4_CMP", "Loop bound CMP #256 (possible KSA loop bound)")
            hits += 1
        if ("and" in s or "and.b" in s) and ("#0xff" in s or "#255" in s):
            note(a, BOOKMARK_RC4, "RC4_AND", "AND #0xFF (index modulo byte mask)")
            hits += 1
        if "mov.b" in s and ("(" in s and ")" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "RC4_INDEXED", "MOV.B indexed memory (S[i] or key lookup)")
            hits += 1
            recent_movs.append((a, s))
            if len(recent_movs) > 6:
                recent_movs.pop(0)
        if ("add.b" in s or "add" in s) and ("(" in s and ")" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "RC4_ADD_MEM", "ADD from memory (possible j += S[i] or j += key)")
            hits += 1
        if ("xor" in s or "xor.b" in s) and ("(" in s and ")" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "RC4_XOR", "XOR with memory indexed (possible keystream output)")
            hits += 1
        if len(recent_movs) >= 3:
            memcount = sum(1 for (_,txt) in recent_movs[-3:] if "(" in txt or "@r" in txt)
            regs = set()
            for (_,txt) in recent_movs[-3:]:
                for tok in re.split(r'[\s,()]+', txt):
                    if tok.startswith("r") and tok[1:].isdigit():
                        regs.add(tok)
            if memcount >= 2 and len(regs) >= 2:
                for (aa,txt) in recent_movs[-3:]:
                    note(aa, BOOKMARK_RC4, "RC4_SWAP", "Swap-like MOV.B sequence (part of S[i]<->S[j])")
                    hits += 1
                recent_movs = []
    return hits

def mark_xtea_instr_patterns(func):
    """
    Bookmark instructions referencing TEA/XTEA constants or ARX operations.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: Hit count
    :rtype: int
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
        if ("add" in s or "xor" in s or "rol" in s or "ror" in s or "lsl" in s or "lsr" in s) and ("r" in s):
            note(a, BOOKMARK_XTEA, "XTEA_ARX", "ARX-like op (add/xor/rotate) -- possible TEA/XTEA")
            hits += 1
    return hits

def mark_prng_instr_patterns(func):
    """
    Bookmark instructions containing PRNG constants (Park-Miller, Knuth, LCG).

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: Hit count
    :rtype: int
    """

    hits = 0
    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        if "16807" in s or "127773" in s or "2836" in s or "0x41a7" in s:
            note(a, BOOKMARK_PRNG, "PRNG_PM", "Park-Miller related constant used")
            hits += 1
        if "161803398" in s or "1000000000" in s or "0x5f5e100" in s:
            note(a, BOOKMARK_PRNG, "PRNG_KNUTH", "Knuth subtractive related constant used")
            hits += 1
        if "1103515245" in s or "0x41c64e6d" in s:
            note(a, BOOKMARK_PRNG, "PRNG_LCG", "LCG-like constant referenced")
            hits += 1
    return hits

def detect_rc4_in_decomp(ctext):
    """
    Detect RC4-like KSA or PRGA patterns in decompiled C text.

    :param ctext: Decompiled C text
    :type ctext: str
    :return: Tuple (ksa_found, prga_found)
    :rtype: tuple
    """

    if ctext is None:
        return (False, False)
    low = ctext.lower()
    ksa = RE_FOR_256.search(low) and (RE_MASK_0xFF.search(low) or RE_KEY_MOD.search(low) or RE_SWAP.search(low))
    prga = RE_PRGA_I.search(low) and (RE_PRGA_J.search(low) or RE_PRGA_OUT.search(low) or ("s[" in low and "^" in low))
    return (bool(ksa), bool(prga))

def find_static_key_from_decomp(ctext):
    """
    Try to locate a static key array referenced by decompiled code.

    :param ctext: Decompiled C text
    :type ctext: str
    :return: Dict with name, addr, bytes or None
    :rtype: dict
    """

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
    """
    Emulate RC4 KSA to produce a 256-byte state S for a given key.

    :param key_bytes: Key byte array or string
    :type key_bytes: list or str or bytearray
    :return: S array as list of ints
    :rtype: list
    """

    S = list(range(256)); j = 0; klen = len(key_bytes)
    if klen == 0:
        return S
    for i in range(256):
        kb = key_bytes[i % klen]
        if isinstance(kb, int):
            kv = kb & 0xff
        else:
            try:
                kv = ord(kb) & 0xff
            except:
                kv = 0
        j = (j + S[i] + kv) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def compare_emulated_to_table(emuS, table_addr):
    """
    Compare an emulated S array to a 256-byte table at table_addr.

    :param emuS: Emulated S array
    :type emuS: list
    :param table_addr: Address of 256-byte table
    :type table_addr: Address
    :return: True if equal
    :rtype: bool
    """

    obs = read_bytes(table_addr, 256)
    if obs is None: return False
    for i in range(256):
        vi = obs[i]
        if vi < 0:
            vi = vi & 0xff
        if (emuS[i] & 0xff) != (vi & 0xff):
            return False
    return True

# ---------------- RC4-like variants: VMPC and RC4A ----------------

def _count_indexed_arrays_in_text(low_text):
    """
    Count array identifiers used in bracket indexing in decompiled text.

    :param low_text: Lowercased C text
    :type low_text: str
    :return: Map of name to count
    :rtype: dict
    """

    names = RE_INDEXED_ARRAY.findall(low_text)
    counts = {}
    for n in names:
        counts[n] = counts.get(n, 0) + 1
    return counts

def detect_vmpc_in_decomp(ctext):
    """
    Heuristic VMPC detection in messy decompiled text.

    :param ctext: Decompiled C text
    :type ctext: str
    :return: True if likely VMPC-like
    :rtype: bool
    """

    if ctext is None:
        return False
    low = ctext.lower()
    nested_hit = RE_NESTED_ARRAY.search(low) is not None
    mask_hit = ("& 0xff" in low) or ("% 256" in low) or ("&0xff" in low)
    arr_counts = _count_indexed_arrays_in_text(low)
    has_arrays = sum(arr_counts.values()) >= 6
    return bool(nested_hit and mask_hit and has_arrays)

def detect_rc4a_in_decomp(ctext):
    """
    Heuristic RC4A detection in messy decompiled text.

    :param ctext: Decompiled C text
    :type ctext: str
    :return: True if likely RC4A-like
    :rtype: bool
    """

    if ctext is None:
        return False
    low = ctext.lower()
    arr_counts = _count_indexed_arrays_in_text(low)
    if len(arr_counts) < 2:
        return False
    tops = sorted(arr_counts.items(), key=lambda x: -x[1])[:2]
    two_heavy = len(tops) == 2 and tops[0][1] >= 3 and tops[1][1] >= 3
    xor_two_arrays = RE_ARRAY_XOR.search(low) is not None
    return bool(two_heavy or xor_two_arrays)

def mark_vmpc_rc4a_instr_patterns(func):
    """
    Bookmark instruction windows suggesting VMPC or RC4A.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: Hit count
    :rtype: int
    """

    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    hits = 0
    window = []
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        indexed = ("mov.b" in s and ("(" in s and ")" in s or "@r" in s))
        if indexed:
            window.append((a, s))
            if len(window) > 8:
                window.pop(0)
        if ("add" in s or "xor" in s) and ("(" in s or "@r" in s):
            note(a, BOOKMARK_RC4, "VMPC_IDX", "Memory based index arithmetic (VMPC-like hint)")
            hits += 1
        if len(window) >= 5:
            memops = sum(1 for (_,txt) in window if ("(" in txt or "@r" in txt))
            if memops >= 4:
                for (aa,txt) in window[-4:]:
                    note(aa, BOOKMARK_RC4, "RC4VAR_WIN", "Dense indexed MOV.B window (RC4-like variant hint)")
                    hits += 1
                window = []
    return hits

def find_adjacent_256_table_pairs(tables, max_gap=64):
    """
    Find pairs of 256-byte tables near each other, hinting RC4A S1/S2.

    :param tables: List of 256-table addresses
    :type tables: list
    :param max_gap: Maximum gap bytes between tables
    :type max_gap: int
    :return: List of tuple pairs
    :rtype: list
    """

    offs = [(t, t.getOffset()) for t in tables]
    offs_sorted = sorted(offs, key=lambda x: x[1])
    pairs = []
    for i in range(len(offs_sorted) - 1):
        a, ao = offs_sorted[i]
        b, bo = offs_sorted[i+1]
        gap = bo - ao - 256
        if gap >= 0 and gap <= max_gap:
            pairs.append((a, b))
            note(a, BOOKMARK_TABLE, "RC4A_SBOX_PAIR", "Two 256-byte permutations near each other (RC4A candidate)")
    return pairs

def mark_rc4_like_variants_in_function(func, ctext):
    """
    Run decomp and instruction heuristics for RC4-like variants.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :param ctext: Decompiled C text
    :type ctext: str
    :return: Dict with flags and counts
    :rtype: dict
    """

    res = {"vmpc": False, "rc4a": False, "instr_hits": 0}
    try:
        if ctext:
            try:
                if detect_vmpc_in_decomp(ctext):
                    note(func.getEntryPoint(), BOOKMARK_RC4, "VMPC_C", "VMPC-like pattern in decompiler output")
                    res["vmpc"] = True
            except:
                pass
            try:
                if detect_rc4a_in_decomp(ctext):
                    note(func.getEntryPoint(), BOOKMARK_RC4, "RC4A_C", "RC4A-like pattern in decompiler output")
                    res["rc4a"] = True
            except:
                pass
        res["instr_hits"] += mark_vmpc_rc4a_instr_patterns(func)
    except:
        pass
    return res

def analyze_functions_marking(tables):
    """
    Decompile and annotate functions with crypto and PRNG heuristics.

    :param tables: List of 256-table addresses
    :type tables: list
    :return: Summary counts
    :rtype: dict
    """

    rc4_c_count = 0
    xtea_count = 0
    prng_func_count = 0
    vmpc_count = 0
    rc4a_func_count = 0
    modulo_total = 0
    for f in fm.getFunctions(True):
        try:
            ctext = decompile_function(f)
            if ctext:
                ksa, prga = detect_rc4_in_decomp(ctext)
                if ksa or prga:
                    note(f.getEntryPoint(), BOOKMARK_RC4, "RC4_C", "RC4-like (decomp): KSA=%s PRGA=%s" % (str(ksa), str(prga)))
                    rc4_c_count += 1
                var_res = mark_rc4_like_variants_in_function(f, ctext)
                if var_res.get("vmpc"):
                    vmpc_count += 1
                if var_res.get("rc4a"):
                    rc4a_func_count += 1
                mark_rc4_instr_patterns(f)
                if RE_XTEA_ARX.search(ctext):
                    note(f.getEntryPoint(), BOOKMARK_XTEA, "XTEA_FUNC", "XTEA/TEA-like (decompiler pattern)")
                    xtea_count += 1
                if RE_PRNG_PM.search(ctext) or RE_PRNG_KNUTH.search(ctext) or RE_LCG.search(ctext):
                    note(f.getEntryPoint(), BOOKMARK_PRNG, "PRNG_FUNC", "PRNG-like pattern in decompiler")
                    prng_func_count += 1
            mark_xtea_instr_patterns(f)
            mark_prng_instr_patterns(f)
            modulo_total += mark_modulo_patterns(f)
        except:
            pass
    return {"rc4_c": rc4_c_count, "xtea": xtea_count, "prng_funcs": prng_func_count, "vmpc": vmpc_count, "rc4a": rc4a_func_count, "mod_hits": modulo_total}

def detect_rc4_asm_in_function(func):
    """
    Score a function for RC4-like assembly patterns.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: Dict with score, flags, and pcs list
    :rtype: dict
    """

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
        if "cmp" in s and ("#0x100" in s or "#256" in s):
            score += 3; flags.add("cmp_256"); pcs.append(a)
            note(a, BOOKMARK_RC4, "RC4_CMP", "CMP #256 (KSA bound?)")
        if ("and" in s or "and.b" in s) and ("#0xff" in s or "#255" in s):
            score += 2; flags.add("and_ff"); pcs.append(a)
            note(a, BOOKMARK_RC4, "RC4_AND", "AND #0xFF")
        if ("inc" in s or ("add" in s and "#1" in s)):
            score += 1; pcs.append(a)
        if "mov.b" in s and ("(" in s and ")" in s or "@r" in s):
            score += 2; flags.add("mov_index"); pcs.append(a)
            recent_movs.append((a,s))
            if len(recent_movs)>6: recent_movs.pop(0)
        if ("add.b" in s or "add" in s) and ("(" in s and ")" in s or "@r" in s):
            score += 2; flags.add("add_mem"); pcs.append(a)
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
    """
    Annotate functions that score high on RC4-like assembly patterns.

    :return: Count of functions marked
    :rtype: int
    """

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
    """
    Scan initialized memory and instructions for PRNG and crypto-related constants.

    :return: Dict with data hits and instruction hits
    :rtype: dict
    """

    results = []
    needles = {
        PM_IA: "Park-Miller IA", PM_IM: "Park-Miller IM",
        PM_IQ: "Park-Miller IQ", PM_IR: "Park-Miller IR",
        KNUTH_MBIG: "Knuth MBIG", KNUTH_MSEED: "Knuth MSEED",
        TEA_DELTA: "TEA delta", TEA_SUM32: "TEA sum32",
        CRC32_POLY: "CRC32 poly"
    }
    le_map = {}
    int_types = (int,)
    for const_val, name in needles.items():
        if not isinstance(const_val, int_types):
            continue
        b = bytearray([(const_val & 0xff), ((const_val>>8)&0xff), ((const_val>>16)&0xff), ((const_val>>24)&0xff)])
        le_map[bytes(b)] = (const_val, name)
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
    """
    Bookmark instructions that touch known IO registers.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: List of (addr, regname) hits
    :rtype: list
    """

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
    Scan initialized memory for common CRC16 polynomials in little endian.

    :return: List of addresses where CRC16 poly bytes occur
    :rtype: list
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

# ---------- Runtime RC4 S detection (ASM-based) ----------

def _parse_imm(valstr):
    """
    Parse an immediate string which may be hex or decimal.

    :param valstr: Immediate literal like 0x100 or 256
    :type valstr: str
    :return: Integer value or None
    :rtype: int
    """

    try:
        if valstr.startswith("0x") or valstr.startswith("0X"):
            return int(valstr, 16)
        return int(valstr)
    except:
        return None

def _find_recent_base_for_reg(func, regname, start_addr, search_back=40):
    """
    Scan backward in the function for a MOV #imm, reg that sets base.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :param regname: Register name like r12
    :type regname: str
    :param start_addr: Starting address to search backward from
    :type start_addr: Address
    :param search_back: Max instructions to look back
    :type search_back: int
    :return: Base address int or None
    :rtype: int
    """

    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return None
    ins_list = []
    for ins in instrs:
        ins_list.append(ins)
    idx = -1
    for i in range(len(ins_list)):
        if ins_list[i].getAddress() == start_addr:
            idx = i
            break
    if idx < 0:
        return None
    lo = max(0, idx - search_back)
    for j in range(idx-1, lo-1, -1):
        s = ins_list[j].toString().lower()
        m = RE_MOV_IMM_TO_REG.search(s)
        if m:
            imm = m.group(2)
            reg = m.group(3).lower()
            if reg == regname.lower():
                val = _parse_imm(imm)
                return val
    return None

def find_rc4_state_in_ram():
    """
    Detect runtime S initialization buffers by scanning stores and loop bounds.

    :return: List of tuples (kind, addr) where kind is byte or word
    :rtype: list
    """

    runtime_hits = []
    for f in fm.getFunctions(True):
        try:
            instrs = listing.getInstructions(f.getBody(), True)
        except:
            continue
        store_events = {}
        cmp256_seen = False
        for ins in instrs:
            s = ins.toString().lower()
            a = ins.getAddress()
            if RE_CMP_256.search(s):
                cmp256_seen = True
            mb = RE_MOVB_STORE_IDX.search(s)
            if mb:
                off_str, reg = mb.group(1), mb.group(2)
                try:
                    off_val = int(off_str)
                except:
                    off_val = 0
                key = ("byte", reg.lower())
                arr = store_events.get(key, [])
                arr.append((a, off_val))
                store_events[key] = arr
                continue
            mw = RE_MOVW_STORE_IDX.search(s)
            if mw:
                off_str, reg = mw.group(2), mw.group(3)
                try:
                    off_val = int(off_str)
                except:
                    off_val = 0
                key = ("word", reg.lower())
                arr = store_events.get(key, [])
                arr.append((a, off_val))
                store_events[key] = arr
                continue
        for (kind, reg), evts in store_events.items():
            if len(evts) < 32:
                continue
            offs = sorted(set([o for (_,o) in evts]))
            if kind == "byte":
                min_off = min(offs); max_off = max(offs)
                cover = (max_off - min_off + 1)
                dense = (cover >= 200) and (len(offs) >= 128)
                if dense and cmp256_seen:
                    base_addr_val = _find_recent_base_for_reg(f, reg, evts[0][0])
                    if base_addr_val is not None:
                        addr = toAddr(base_addr_val + min_off)
                        note(addr, BOOKMARK_TABLE, "RC4_SBOX_RUNTIME", "Runtime RC4 S[] buffer candidate at base reg %s" % reg)
                        runtime_hits.append(("byte", addr))
                    else:
                        note(f.getEntryPoint(), BOOKMARK_TABLE, "RC4_SBOX_RUNTIME", "Runtime RC4 S[] via %s offsets; base unresolved" % reg)
                        runtime_hits.append(("byte", None))
            else:
                even = all((o % 2) == 0 for o in offs[:64])
                if even and cmp256_seen and (max(offs) >= 300):
                    base_addr_val = _find_recent_base_for_reg(f, reg, evts[0][0])
                    if base_addr_val is not None:
                        addr = toAddr(base_addr_val + min(offs))
                        note(addr, BOOKMARK_TABLE, "RC4_SBOX_RUNTIME16", "Runtime RC4 S[] word buffer candidate at base reg %s" % reg)
                        runtime_hits.append(("word", addr))
                    else:
                        note(f.getEntryPoint(), BOOKMARK_TABLE, "RC4_SBOX_RUNTIME16", "Runtime RC4 S[] word via %s; base unresolved" % reg)
                        runtime_hits.append(("word", None))
    return runtime_hits

# ---------- Global modulo pattern detection ----------

def _is_power_of_two_minus_one(mask):
    """
    Test if mask is of form (2^n - 1).

    :param mask: Integer mask
    :type mask: int
    :return: True if mask is 2^n - 1
    :rtype: bool
    """

    if mask < 1:
        return False
    return ((mask + 1) & mask) == 0

def mark_modulo_patterns(func):
    """
    Detect modulo-like operations in assembly: mask, div remainder, subtract loops, shift+mask.

    :param func: Function to scan
    :type func: ghidra.program.model.listing.Function
    :return: Number of modulo-related bookmarks added
    :rtype: int
    """

    hits = 0
    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return 0
    # collect a small sliding window to relate cmp/sub and shift/mask
    window = []
    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()
        window.append((a, s))
        if len(window) > 8:
            window.pop(0)

        # Masking mod: AND #((2^n)-1)
        m = RE_AND_IMM.search(s)
        if m:
            imm = m.group(2)
            val = _parse_imm(imm)
            if val is not None and _is_power_of_two_minus_one(val):
                nplus = val + 1
                note(a, BOOKMARK_MOD, "MOD_MASK", "AND with mask 0x%X implies mod %d" % (val, nplus))
                hits += 1

        # Division based mod: calls to __div, __divu, __mod, __rem
        if RE_CALL_DIV.search(s):
            note(a, BOOKMARK_MOD, "MOD_DIVCALL", "Division/mod call used (remainder likely used as modulus)")
            hits += 1

        # Subtract loop mod: CMP #N then SUB #N on same register nearby
        mc = RE_CMP_IMM_REG.search(s)
        if mc:
            n_imm = _parse_imm(mc.group(2))
            regc = mc.group(3)
            # search forward a few instructions for SUB #same, reg
            for (aa, ss) in window[-1:]:
                pass  # keep lint quiet
        # check recent window for cmp/sub sequence
        for (aa, ss) in window:
            subm = RE_SUB_IMM_REG.search(ss)
            if subm and mc:
                n2 = _parse_imm(subm.group(2))
                regs = subm.group(3)
                if n_imm is not None and n2 is not None and regs == regc and n2 == n_imm:
                    note(ins.getAddress(), BOOKMARK_MOD, "MOD_SUBLOOP", "CMP and SUB of same constant suggest modulo by %d" % n_imm)
                    hits += 1
                    break

        # Shift plus mask: look for shift in window and power-of-two mask
        if RE_SHIFT.search(s):
            # see if a mask follows soon
            for (wa, ws) in window:
                mm = RE_AND_IMM.search(ws)
                if mm:
                    mv = _parse_imm(mm.group(2))
                    if mv is not None and _is_power_of_two_minus_one(mv):
                        note(wa, BOOKMARK_MOD, "MOD_SHIFTMASK", "Shift and AND 0x%X imply modulo %d" % (mv, mv+1))
                        hits += 1
                        break
    return hits

def main():
    """
    Entry point: run scans, annotate program, and show summary.

    :return: None
    :rtype: None
    """

    print("==== [D430] Crypto Scanner =====")
    start = time.time()
    note(currentProgram.getMinAddress(), BOOKMARK_CRYPTO, "Info", "D430 Scanner mark.")

    # Data scans
    print("[D430] Attempting to find potential S-Box tables")
    tables = find_256_tables()
    aes_hits = find_aes_rcon_and_sboxes()
    crc16_hits = find_crc16_constants()

    # RC4A hint: adjacent S-boxes
    rc4a_pairs = find_adjacent_256_table_pairs(tables)

    # Runtime S detection (ASM-based)
    print("[D430] Scanning for runtime RC4 S initialization")
    runtime_s_hits = find_rc4_state_in_ram()

    # Prng constants scan
    print("[D430] Scanning for constants")
    prng_res = scan_constants_and_prngs_and_mark()

    # Function-level decomp and instr marking (also runs global modulo detection)
    func_summary = analyze_functions_marking(tables)

    # ASM-only RC4 detection (marks instrs in functions too)
    print("[D430] Scanning and marking possible rc4 instructions.")
    rc4_asm_hits = rc4_asm_scan_and_mark()

    # USCI scan
    usci_count = 0
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
    lines.append("RC4 S[] tables (static): %d" % (len(tables),))
    lines.append("RC4 S[] runtime buffers: %d" % (len(runtime_s_hits),))
    lines.append("RC4A S-box pairs: %d" % (len(rc4a_pairs),))
    lines.append("AES/Rcon hits: %d" % (len(aes_hits),))
    lines.append("PRNG constant data hits: %d" % (len(prng_res.get("data", [])),))
    lines.append("PRNG instruction hits: %d" % (prng_res.get("instr_hits", 0),))
    lines.append("RC4 (decompiler) functions: %d" % (func_summary.get("rc4_c",0),))
    lines.append("VMPC-like functions: %d" % (func_summary.get("vmpc",0),))
    lines.append("RC4A-like functions: %d" % (func_summary.get("rc4a",0),))
    lines.append("Modulo pattern bookmarks: %d" % (func_summary.get("mod_hits",0),))
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