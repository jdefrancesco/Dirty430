# -*- coding: utf-8 -*-
# DirtyCrypto.py
#
# - RC4 (256-byte permutation detection, KSA/PRGA heuristics, key extraction, KSA emulation verification)
# - AES S-box / invS-box / Rcon detection
# - XTEA/TEA heuristics (constants and ARX patterns)
# - CRC table heuristics
# - PRNG detection (Knuth subtractive, NR ran1, RANDU, glibc LCG)
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

# ---------------- Config ----------------
BOOKMARK_CRYPTO     = "CRYPTO"
BOOKMARK_RC4        = "CRYPTO_RC4"
BOOKMARK_PRNG       = "CRYPTO_PRNG"
BOOKMARK_CRYPTO_IO  = "CRYPTO_IO"
BOOKMARK_TABLE      = "CRYPTO_TABLE"

MAX_CHUNK = 0x10000
DECOMP_TIMEOUT = 6
KEY_READ_MAX = 64

# MSP430F5438-ish useful regs (for IO correlation, in case symbols lack names)
IO_REGS = {
    "UCA0RXBUF": 0x05cc, "UCA0TXBUF": 0x05ce,
    "UCB0RXBUF": 0x05ec, "UCB0TXBUF": 0x05ee,
    "UCB1RXBUF": 0x062c, "UCB1TXBUF": 0x062e,
    "P1OUT": 0x0202, "P2OUT": 0x0203, "P3OUT": 0x0222, "P4OUT": 0x0223
}

# crypto signatures
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
KNUTH_N = 55

# regex heuristics (decompiler text)
RE_FOR_256    = re.compile(r'\bfor\b[^;]*;\s*i\s*<\s*256\b', re.IGNORECASE)
RE_MASK_0xFF  = re.compile(r'&\s*0x?ff\b', re.IGNORECASE)
RE_KEY_MOD    = re.compile(r'([A-Za-z_0-9]+)\s*\[\s*i\s*%\s*([0-9A-Za-z_]+)\s*\]', re.IGNORECASE)
RE_SWAP       = re.compile(r'swap\s*\(|tmp\s*=.*s\[', re.IGNORECASE)
RE_PRGA_I     = re.compile(r'i\s*=\s*\(?i\s*\+\s*1\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_J     = re.compile(r'j\s*=\s*\(?j\s*\+\s*s\[\s*i\s*\]\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_OUT   = re.compile(r'\^\s*s\[\s*\(s\[.*i.*\]\s*\+\s*s\[.*j.*\]\s*\)\s*&\s*0x?ff', re.IGNORECASE)
RE_XTEA_ARX   = re.compile(r'<<\s*4|>>\s*5|0x9e3779b9', re.IGNORECASE)
RE_PRNG_PM    = re.compile(r'16807|127773|2836|0x41a7|0x1f31d|0x0b14', re.IGNORECASE)
RE_PRNG_KNUTH = re.compile(r'161803398|1000000000|55|24', re.IGNORECASE)
RE_LCG        = re.compile(r'1103515245|12345|65539|0x41c64e6d|0x3039|0x00010003', re.IGNORECASE)

# ghidra objects
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
bkm     = currentProgram.getBookmarkManager()
fm      = currentProgram.getFunctionManager()
symtab  = currentProgram.getSymbolTable()
refmgr  = currentProgram.getReferenceManager()

def note(addr, category, kind, msg):
    try: bkm.setBookmark(addr, category, kind, msg)
    except: pass
    try: listing.setComment(addr, CodeUnit.PLATE_COMMENT, "[%s] %s" % (category, msg))
    except: pass
    print("%s | %s @ %s : %s" % (category, kind, addr.toString(), msg))

def read_bytes(addr, n):
    try:
        bb = bytearray(n); memory.getBytes(addr, bb); return bb
    except: return None

def u32_le(bb, i):
    if i+4>len(bb): return None
    return (bb[i] | (bb[i+1]<<8) | (bb[i+2]<<16) | (bb[i+3]<<24)) & 0xffffffff

def decompile_function(func, timeout=DECOMP_TIMEOUT):
    try:
        ifc = DecompInterface(); ifc.openProgram(currentProgram)
        res = ifc.decompileFunction(func, timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted(): return None
        return res.getDecompiledFunction().getC()
    except: return None

def read_reset_vector():
    # MSP430 classic reset vector at 0xFFFE (16-bit little-endian)
    # Not required for analysis, but nice to report for flat/raw loads.
    try:
        va = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(0xFFFF & 0xFFFE)
        bb = read_bytes(va, 2)
        if bb is None: return None
        entry_lo = bb[0] | (bb[1]<<8)
        return entry_lo
    except:
        return None

def is_256_permutation(bb, off=0):
    if bb is None or off+256>len(bb): return False
    seen = [False]*256
    for i in range(256):
        v = bb[off+i]
        if seen[v]: return False
        seen[v] = True
    return True

def find_256_tables():
    hits = []
    for blk in memory.getBlocks():
        if not blk.isInitialized(): continue
        base = blk.getStart(); size = blk.getSize(); off = 0
        while off < size:
            chunk = min(MAX_CHUNK, size-off)
            baddr = base.add(off)
            bb = read_bytes(baddr, chunk); 
            if bb is None: off += chunk; continue
            i=0
            while i+256 <= len(bb):
                if is_256_permutation(bb, i):
                    a = baddr.add(i)
                    hits.append(a)
                    note(a, BOOKMARK_TABLE, "RC4_SBOX", "256-byte permutation (S[] candidate)")
                    i += 256; continue
                i += 1
            off += chunk
    return hits

def find_aes_rcon_and_sboxes():
    hits=[]
    for blk in memory.getBlocks():
        if not blk.isInitialized(): continue
        base = blk.getStart(); size=blk.getSize(); off=0
        while off<size:
            chunk = min(MAX_CHUNK, size-off); baddr = base.add(off)
            bb = read_bytes(baddr, chunk); 
            if bb is None: off+=chunk; continue
            L=len(bb)
            for i in range(0,L-4+1):
                if bb[i:i+4] == bytearray(AES_SBOX_HEAD):
                    a=baddr.add(i); hits.append((a,"AES_SBOX")); note(a, BOOKMARK_TABLE,"AES","AES S-box header")
                if bb[i:i+4] == bytearray(AES_INV_HEAD):
                    a=baddr.add(i); hits.append((a,"AES_INV")); note(a, BOOKMARK_TABLE,"AES","AES inverse S-box header")
                if i+len(AES_RCON_SEQ)<=L:
                    ok=True
                    for j,v in enumerate(AES_RCON_SEQ):
                        if bb[i+j]!=v: ok=False; break
                    if ok:
                        a=baddr.add(i); hits.append((a,"AES_RCON")); note(a, BOOKMARK_TABLE,"AES","AES Rcon sequence")
            off+=chunk
    return hits

def find_crc32_tables():
    hits=[]
    for blk in memory.getBlocks():
        if not blk.isInitialized(): continue
        base=blk.getStart(); size=blk.getSize(); off=0
        while off<size:
            chunk=min(MAX_CHUNK,size-off); baddr=base.add(off)
            bb=read_bytes(baddr,chunk); 
            if bb is None: off+=chunk; continue
            L=len(bb); i=0
            while i+1024<=L:
                some=False
                for k in range(0,1024,4):
                    v=u32_le(bb,i+k)
                    if v is None: break
                    if v!=0: some=True; break
                if some:
                    a=baddr.add(i); hits.append(a)
                    note(a, BOOKMARK_TABLE,"CRC","Possible 256x4 CRC table")
                i+=1
            off+=chunk
    return hits

def detect_rc4_in_decomp(ctext):
    if ctext is None: return (False,False)
    low = ctext.lower()
    ksa = RE_FOR_256.search(low) and (RE_MASK_0xFF.search(low) or RE_KEY_MOD.search(low) or RE_SWAP.search(low))
    prga = RE_PRGA_I.search(low) and (RE_PRGA_J.search(low) or RE_PRGA_OUT.search(low) or ("s[" in low and "^" in low))
    return (bool(ksa), bool(prga))

def find_static_key_from_decomp(ctext):
    if ctext is None: return None
    low=ctext.lower()
    m = RE_KEY_MOD.search(low)
    syms = symtab
    if m:
        name=m.group(1)
        try:
            for s in syms.getSymbols(name):
                a=s.getAddress()
                if a and memory.contains(a):
                    bb=read_bytes(a, KEY_READ_MAX)
                    if bb is not None:
                        return {"name": name, "addr": a, "bytes": bb}
        except: pass
    for tok in re.findall(r'dat_[0-9a-f]{4,}', ctext, re.IGNORECASE):
        try:
            for s in syms.getSymbols(tok):
                a=s.getAddress()
                if a and memory.contains(a):
                    bb=read_bytes(a, KEY_READ_MAX)
                    if bb is not None:
                        return {"name": tok, "addr": a, "bytes": bb}
        except: pass
    try:
        for s in syms.getSymbols("key"):
            a=s.getAddress()
            if a and memory.contains(a):
                bb=read_bytes(a, KEY_READ_MAX)
                if bb: return {"name":"key","addr":a,"bytes":bb}
    except: pass
    return None

def rc4_ksa_emulate(key_bytes):
    S=list(range(256)); j=0; klen=len(key_bytes)
    for i in range(256):
        j = (j + S[i] + (key_bytes[i % klen] & 0xff)) & 0xff
        S[i],S[j] = S[j],S[i]
    return S

def compare_emulated_to_table(emuS, taddr):
    obs=read_bytes(taddr,256)
    if obs is None: return False
    for i in range(256):
        if (emuS[i]&0xff)!=(obs[i]&0xff): return False
    return True

def detect_rc4_asm_in_function(func):
    """
    Score-based pattern detector (no decompiler) for MSP430:
      - Loop to 256 (CMP #0x100 / JNE/JLO/JC) OR many AND #0xFF masks
      - Byte-indexed memory moves MOV.B x(Rn), Rm (array access)
      - Swap pattern via three MOV.B in short window
      - Updates to two "index" registers (INC/ADD #1) plus AND #0xFF
      - Optional ADD.B from S[i] and/or key[...] into 'j' reg
    Returns: {'score':N, 'flags':set([...]), 'pcs': [addresses contributing]}
    """
    score = 0
    flags = set()
    pcs   = []

    # Sliding window of last few MOV.B to spot swap patterns
    last_movb = []

    has_256_cmp  = False
    and_ff_count = 0
    inc_i_like   = 0
    inc_j_like   = 0
    indexed_refs = 0
    swap_hits    = 0
    add_from_mem = 0

    it = listing.getInstructions(func.getBody(), True)
    for ins in it:
        t = ins.toString().lower()
        pc = ins.getAddress()

        if "cmp" in t and ("#0x100" in t or "#256" in t):
            has_256_cmp = True; score += 2; pcs.append(pc)

        if ("and.b" in t or "and" in t) and "#0xff" in t:
            and_ff_count += 1; score += 1; pcs.append(pc)

        # i/j updates (very heuristic): INC, ADD #1
        if ("inc" in t) or ("add" in t and "#1" in t):
            # don't know which is i or j; count both as index updates
            score += 1; pcs.append(pc)

        # Indexed memory patterns: x(Rn) or @Rn
        if "mov.b" in t and ("(" in t and ")" in t or "@r" in t):
            indexed_refs += 1; score += 1; pcs.append(pc)
            # consider for swap pattern window
            last_movb.append((pc, t))
            if len(last_movb) > 4:
                last_movb.pop(0)

            # crude swap recognizer: 3 mov.b within small window and two distinct memory refs
            if len(last_movb) >= 3:
                memlike = 0
                regs    = set()
                for _, mt in last_movb[-3:]:
                    if "(" in mt or "@r" in mt: memlike += 1
                    # gather some register tokens to see variety
                    for token in mt.replace(",", " ").split():
                        if token.startswith("r") and token[1:].isdigit():
                            regs.add(token)
                if memlike >= 2 and len(regs) >= 2:
                    swap_hits += 1
                    score += 2
                    flags.add("swap_seq")

        # ADD.B something from memory -> j
        if ("add.b" in t or "add" in t) and (("(" in t and ")" in t) or "@r" in t):
            add_from_mem += 1; score += 1; pcs.append(pc)

        # PRGA often has XOR.B with S[ S[i] + S[j] ]
        if ("xor.b" in t or "xor" in t) and (("(" in t and ")" in t) or "@r" in t):
            flags.add("xor_keystream"); score += 1; pcs.append(pc)

        # check for conditional jump typical of loops
        if ("jne" in t or "jc" in t or "jnz" in t) and ("cmp" not in t):
            # weak signal: loops present
            score += 0.5

    # Decide if KSA or PRGA heuristics triggered
    if has_256_cmp and and_ff_count >= 2 and swap_hits >= 1 and indexed_refs >= 4:
        flags.add("KSA_like")
        score += 3
    if "xor_keystream" in flags and and_ff_count >= 1 and indexed_refs >= 3 and swap_hits >= 1:
        flags.add("PRGA_like")
        score += 2

    return {"score": score, "flags": flags, "pcs": pcs}

def rc4_asm_scan():
    """Scan all functions; bookmark ASM-only RC4 KSA/PRGA detections."""
    hits = 0
    for f in fm.getFunctions(True):
        try:
            res = detect_rc4_asm_in_function(f)
            if res["score"] < 5:  # threshold to reduce noise
                continue
            ep = f.getEntryPoint()
            if "KSA_like" in res["flags"]:
                note(ep, BOOKMARK_RC4, "RC4_ASM_KSA", "Assembly-level RC4 KSA-like pattern (score=%s)" % str(res["score"]))
                hits += 1
            if "PRGA_like" in res["flags"]:
                note(ep, BOOKMARK_RC4, "RC4_ASM_PRGA", "Assembly-level RC4 PRGA-like pattern (score=%s)" % str(res["score"]))
                hits += 1
        except:
            pass
    return hits

def detect_prng_in_decomp(ctext):
    tags=[]
    if ctext is None: return tags
    low=ctext.lower()
    if RE_PRNG_PM.search(low): tags.append("Park-Miller/Bays-Durham")
    if RE_PRNG_KNUTH.search(low): tags.append("Knuth_subtractive")
    if RE_LCG.search(low): tags.append("LCG/RANDU-like")
    return tags

def scan_constants_and_prngs():
    const_hits = []
    blocks = memory.getBlocks()

    needles = {
        PM_IA: "Park-Miller IA", PM_IM: "Park-Miller IM",
        PM_IQ: "Park-Miller IQ", PM_IR: "Park-Miller IR",
        KNUTH_MBIG: "Knuth MBIG", KNUTH_MSEED: "Knuth MSEED",
        TEA_DELTA: "TEA delta", TEA_SUM32: "TEA sum32",
        CRC32_POLY: "CRC32 poly"
    }

    le_map = {}
    int_types = (int,)
    try:
        long
        int_types = (int,long)
    except: pass

    for const_val, const_name in needles.items():
        if not isinstance(const_val, int_types):
            continue
        b0 = const_val & 0xff
        b1 = (const_val>>8) & 0xff
        b2 = (const_val>>16)& 0xff
        b3 = (const_val>>24)& 0xff
        try:
            k = bytes(bytearray([b0,b1,b2,b3]))
        except:
            k = str(bytearray([b0,b1,b2,b3]))
        le_map[k] = (const_val, const_name)

    for blk in blocks:
        if not blk.isInitialized(): continue
        base=blk.getStart(); size=blk.getSize(); off=0
        while off<size:
            chunk=min(MAX_CHUNK,size-off); baddr=base.add(off)
            bb=read_bytes(baddr,chunk)
            if bb is None: off+=chunk; continue
            for i in range(0,len(bb)-4+1):
                try: key=bytes(bb[i:i+4])
                except: key=str(bytearray(bb[i:i+4]))
                if key in le_map:
                    val,name = le_map[key]
                    a=baddr.add(i)
                    note(a, BOOKMARK_PRNG, "Const", "Found %s (%s)" % (hex(val), name))
                    const_hits.append((a,val,name))
            off+=chunk

    # decompiler PRNG hints
    prng_func_hits = 0
    for f in fm.getFunctions(True):
        c = decompile_function(f)
        if not c: continue
        tags = detect_prng_in_decomp(c)
        if tags:
            note(f.getEntryPoint(), BOOKMARK_PRNG, "Function", "PRNG hints: " + ", ".join(tags))
            prng_func_hits += 1

    return {"consts": const_hits, "func_hits": prng_func_hits}

def detect_xtea_in_decomp(ctext):
    if ctext is None: return False
    return bool(RE_XTEA_ARX.search(ctext))


def func_accesses_io(func):
    hits=[]
    try:
        for ins in listing.getInstructions(func.getBody(), True):
            s = ins.toString().lower()
            for name,addr in IO_REGS.items():
                if name.lower() in s or hex(addr)[2:].lower() in s:
                    hits.append((ins.getAddress(), name))
    except: pass
    return hits

def analyze_functions(tables):
    rc4_c_count = 0
    xtea_count  = 0
    for f in fm.getFunctions(True):
        try:
            ctext = decompile_function(f)
            if ctext:
                ksa,prga = detect_rc4_in_decomp(ctext)
                if ksa or prga:
                    note(f.getEntryPoint(), BOOKMARK_RC4, "RC4_C", "RC4-like (decomp): KSA=%s PRGA=%s" % (str(ksa),str(prga)))
                    rc4_c_count += 1
                if detect_xtea_in_decomp(ctext):
                    note(f.getEntryPoint(), BOOKMARK_CRYPTO, "XTEA", "XTEA/TEA-like ARX pattern/delta")
                    xtea_count += 1

            # correlate with I/O
            io_hits = func_accesses_io(f)
            if io_hits and (ctext and ("s[" in ctext.lower() or "rc4" in ctext.lower())):
                note(f.getEntryPoint(), BOOKMARK_CRYPTO_IO, "Correlation", "Crypto + USCI I/O in same function")

        except: pass
    return {"rc4_c": rc4_c_count, "xtea": xtea_count}

# ---------- USCI scan (names if present) ----------
def get_symbol_addr_exact(name):
    try:
        for s in symtab.getSymbols(name):
            if s.getName()==name: return s.getAddress()
    except: pass
    return None

def get_symbols_matching(regex):
    res=[]; 
    try:
        it=symtab.getAllSymbols(False); pat=re.compile(regex)
        while it.hasNext():
            s=it.next()
            if pat.match(s.getName()): res.append(s)
    except: pass
    return res

def collect_known_regs():
    modules={"UCA0":{}, "UCA1":{}, "UCB0":{}, "UCB1":{}}
    reg_names=["CTL0","CTL1","BR0","BR1","MCTL","STAT","RXBUF","TXBUF","ABCTL","IRCTL","I2CSA","IE","IFG"]
    for mod in modules.keys():
        for r in reg_names:
            a=get_symbol_addr_exact(mod+r)
            if a is not None: modules[mod][r]=a
        if len(modules[mod])==0:
            syms=get_symbols_matching(r"(?i)^"+mod+r"[A-Z0-9_]*$")
            for s in syms:
                nm=s.getName().upper()
                for r in reg_names:
                    if r in nm: modules[mod][r]=s.getAddress()
    return modules

def is_write_to(addr, ins_text):
    s=ins_text.lower(); a=addr.toString().lower()
    return (("mov" in s or "add" in s or "bis" in s or "bic" in s) and (a in s))

def nearby_port_writes(func):
    hits=[]
    p_syms = get_symbols_matching(r"(?i)^P([1-9]|10)(DIR|SEL|OUT)$")
    if len(p_syms)==0: return hits
    for ins in listing.getInstructions(func.getBody(), True):
        t=ins.toString()
        for s in p_syms:
            if is_write_to(s.getAddress(), t):
                hits.append((ins.getAddress(), s.getName(), t))
    return hits

def analyze_module_in_function(func, mod, regs):
    if len(regs)==0: return None
    observed={"writes":[], "reads":[], "tx_hits":[], "rx_hits":[], "i2c_addr_write":False}
    for ins in listing.getInstructions(func.getBody(), True):
        t=ins.toString().lower()
        touches=False
        if mod.lower() in t:
            touches=True
        else:
            for raddr in regs.values():
                if raddr.toString().lower() in t:
                    touches=True; break
        if not touches: continue
        for rname,raddr in regs.items():
            ahex=raddr.toString().lower()
            if ahex in t:
                if is_write_to(raddr, ins.toString()):
                    observed["writes"].append((ins.getAddress(), rname, ins.toString()))
                    if rname=="I2CSA": observed["i2c_addr_write"]=True
                else:
                    observed["reads"].append((ins.getAddress(), rname, ins.toString()))
                if rname=="TXBUF": observed["tx_hits"].append((ins.getAddress(), ins.toString()))
                if rname=="RXBUF": observed["rx_hits"].append((ins.getAddress(), ins.toString()))
    if len(observed["writes"])==0 and len(observed["tx_hits"])==0 and len(observed["rx_hits"])==0:
        return None

    if observed["i2c_addr_write"]:
        mode="I2C (UCBxI2CSA written)"
    elif len(observed["tx_hits"])>0:
        mode="SPI likely (TXBUF activity)" if mod.startswith("UCB") else "UART/SPI (TXBUF activity)"
    else:
        mode="Unknown"

    note(func.getEntryPoint(), BOOKMARK_CRYPTO_IO, "USCI", "%s in %s — %d TX, %d RX" % (mod, mode, len(observed["tx_hits"]), len(observed["rx_hits"])))
    for (a,rn,_) in observed["writes"]:
        note(a, BOOKMARK_CRYPTO_IO, "USCI_WRITE", mod+rn+" write")
    for (a,_) in observed["tx_hits"]:
        note(a, BOOKMARK_CRYPTO_IO, "USCI_TX", mod+" TXBUF write")
    for (a,_) in observed["rx_hits"]:
        note(a, BOOKMARK_CRYPTO_IO, "USCI_RX", mod+" RXBUF read")

    for (paddr,pname,_) in nearby_port_writes(func):
        note(paddr, BOOKMARK_CRYPTO_IO, "PORT_CFG", "Port cfg near USCI: "+pname)
    return True

def scan_usci_modules():
    mods=collect_known_regs()
    count=0
    for f in fm.getFunctions(True):
        for mod,regs in mods.items():
            if len(regs)==0: continue
            try:
                if analyze_module_in_function(f,mod,regs): count+=1
            except: pass
    return count


def main():
    start=time.time()

    # Reset vector autodetect
    rv = read_reset_vector()
    if rv is not None:
        # informational only: add bookmark if vector looks sane
        try:
            addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(rv)
            note(addr, BOOKMARK_CRYPTO, "RESET_VECTOR", "Reset vector points to 0x%04x" % rv)
        except: pass

    note(currentProgram.getMinAddress(), BOOKMARK_CRYPTO, "Info", "Mega crypto+PRNG+RC4-ASM scan started")

    # Data scans
    rc4_tables = find_256_tables()
    aes_hits   = find_aes_rcon_and_sboxes()
    crc_hits   = find_crc32_tables()

    # PRNG (const + c-decomp)
    prng_res   = scan_constants_and_prngs()

    # Function scans (C heuristics for RC4/XTEA + I/O correlation)
    fsum       = analyze_functions(rc4_tables)

    # ASM-only RC4 scan (new)
    rc4_asm_hits = rc4_asm_scan()

    # USCI modules (symbols if present)
    usci_funcs = scan_usci_modules()

    elapsed = time.time()-start

    # Summary
    lines=[]
    lines.append("Mega scan complete in %.2f s" % elapsed)
    lines.append("RC4 S[] tables: %d" % len(rc4_tables))
    lines.append("AES/Rcon hits: %d" % len(aes_hits))
    lines.append("CRC-like tables: %d" % len(crc_hits))
    lines.append("PRNG const hits: %d, PRNG func hints: %d" % (len(prng_res.get("consts",[])), prng_res.get("func_hits",0)))
    lines.append("RC4 (decompiler) functions: %d" % fsum.get("rc4_c",0))
    lines.append("RC4 (assembly) detections: %d" % rc4_asm_hits)
    lines.append("XTEA-like functions: %d" % fsum.get("xtea",0))
    lines.append("USCI functions annotated: %d" % usci_funcs)
    print("==== DirtyCrypto Summary ====")
    for l in lines: print(l)
    ta = JTextArea("\n".join(lines), 16, 80); ta.setEditable(False)
    JOptionPane.showMessageDialog(None, JScrollPane(ta), "DirtyCrypto Summary", JOptionPane.PLAIN_MESSAGE)

if __name__ == "__main__":
    main()