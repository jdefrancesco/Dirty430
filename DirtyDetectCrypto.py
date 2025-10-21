# DirtyDetectCrypto.py
#
# Heuristic scanner for crypto patterns in MSP430 (radio firmware) in Ghidra.
# - Detects RC4 (256-byte permutation, KSA, PRGA), AES (S-box, invSbox, Rcon), XTEA/TEA constants,
#   CRC tables, and KDF-like loops.
# - Adds Bookmarks (category "CRYPTO") and Plate comments.
# - Attempts simple key extraction heuristics for RC4/array-backed keys.
#
# Notes:
# - Heuristics only. Expect false positives; use bookmarks as pivots for manual review.
# - Script is conservative and will not overwrite program memory.
#
# @author J. DeFrancesco
# @category MSP430


from ghidra.program.model.address import Address
from ghidra.program.model.listing import CodeUnit
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType
from javax.swing import JOptionPane, JScrollPane, JTextArea
import re, binascii, struct, time

# --- Configurable heuristics ---
MAX_CHUNK = 0x10000       # chunk size to read from memory blocks
MIN_KEY_BYTES = 1
MAX_KEY_BYTES = 256       # when looking for small key arrays
BOOKMARK_CATEGORY = "CRYPTO"

# signatures
AES_SBOX_HEAD = [0x63, 0x7c, 0x77, 0x7b]
AES_INV_HEAD  = [0x52, 0x09, 0x6a, 0xd5]
AES_RCON_SEQ  = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
AES_XTIME     = 0x1b
TEA_DELTA     = 0x9E3779B9
TEA_SUM32     = 0xC6EF3720
CHACHA_CONSTS = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]  # "expand 32-byte k"
CRC32_POLY    = 0xEDB88320
CRC16_POLYS   = [0x1021, 0xA001]

# regex heuristics for decompiled C (lowercased)
RE_KSA_LOOPT = re.compile(r'\bfor\b[^;]*;\s*i\s*<\s*256\b', re.IGNORECASE)
RE_KSA_MASK  = re.compile(r'&\s*0x?ff\b', re.IGNORECASE)
RE_KEY_MOD   = re.compile(r'key\s*\[.*i\s*%.*\]', re.IGNORECASE)
RE_SWAP_TMP  = re.compile(r'tmp\s*=\s*S\[\s*i\s*\]\s*;.*S\[\s*i\s*\]\s*=\s*S\[\s*j\s*\]\s*;.*S\[\s*j\s*\]\s*=\s*tmp', re.IGNORECASE | re.DOTALL)
RE_PRGA_I    = re.compile(r'i\s*=\s*\(?i\s*\+\s*1\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_J    = re.compile(r'j\s*=\s*\(?j\s*\+\s*S\[\s*i\s*\]\)?\s*&\s*0x?ff', re.IGNORECASE)
RE_PRGA_OUT  = re.compile(r'\^\s*S\[\s*\(\s*S\[\s*i\s*\]\s*\+\s*S\[\s*j\s*\]\s*\)\s*&\s*0x?ff\s*\]', re.IGNORECASE)

RE_XTEA_ARX  = re.compile(r'<<\s*4.*>>\s*5|0x9e3779b9', re.IGNORECASE)
RE_KDF_LOOP  = re.compile(r'for\s*\([^;]+;\s*[^;]+;\s*[^)]+\)\s*{', re.IGNORECASE)  # generic loop detection; refined below

# helpers
memory = currentProgram.getMemory()
listing = currentProgram.getListing()
bkm = currentProgram.getBookmarkManager()
fm = currentProgram.getFunctionManager()

def note(addr, kind, msg):
    try:
        bkm.setBookmark(addr, BOOKMARK_CATEGORY, kind, msg)
    except:
        pass
    try:
        listing.setComment(addr, CodeUnit.PLATE_COMMENT, "[CRYPTO] " + msg)
    except:
        pass
    print(kind + " @ " + addr.toString() + " : " + msg)

def read_bytes(addr, length):
    try:
        buf = bytearray(length)
        memory.getBytes(addr, buf)
        return buf
    except Exception as e:
        return None

def u32_le_from(buf, i):
    if i+4 > len(buf):
        return None
    return (buf[i] | (buf[i+1]<<8) | (buf[i+2]<<16) | (buf[i+3]<<24)) & 0xffffffff

def u16_le_from(buf, i):
    if i+2 > len(buf):
        return None
    return (buf[i] | (buf[i+1]<<8)) & 0xffff

# Scan mem blocks
def scan_blocks_for_tables():
    print("[*] Scanning initialized memory blocks for crypto tables...")
    blocks = memory.getBlocks()
    aes_found = 0
    perm_found = 0
    rcon_found = 0
    crc32_found = 0
    for blk in blocks:
        if not blk.isInitialized():
            continue
        start = blk.getStart()
        size = blk.getSize()
        offset = 0
        while offset < size:
            # read chunk
            chunk_len = MAX_CHUNK if (size - offset) > MAX_CHUNK else (size - offset)
            addr = start.add(offset)
            bb = read_bytes(addr, chunk_len)
            if bb is None:
                offset += chunk_len
                continue
            i = 0
            L = len(bb)
            while i < L:
                # AES S-box head
                if i+4 <= L and bb[i:i+4] == bytearray(AES_SBOX_HEAD):
                    note(addr.add(i), "Memory", "AES S-box head match (0x63 0x7c 0x77 0x7b)")
                    aes_found += 1
                # AES inv-sbox head
                if i+4 <= L and bb[i:i+4] == bytearray(AES_INV_HEAD):
                    note(addr.add(i), "Memory", "AES inverse S-box head match (0x52 0x09 0x6a 0xd5)")
                    aes_found += 1
                # AES Rcon sequence
                if i+len(AES_RCON_SEQ) <= L:
                    ok = True
                    for j in range(len(AES_RCON_SEQ)):
                        if bb[i+j] != AES_RCON_SEQ[j]:
                            ok = False
                            break
                    if ok:
                        note(addr.add(i), "Memory", "AES Rcon sequence found")
                        rcon_found += 1
                # 256-byte permutation (RC4 S)
                if i+256 <= L:
                    block = bb[i:i+256]
                    seen = [False]*256
                    ok = True
                    for b in block:
                        if seen[b]:
                            ok = False
                            break
                        seen[b] = True
                    if ok:
                        note(addr.add(i), "Memory", "256-byte permutation (S-box / RC4 candidate)")
                        perm_found += 1
                        i += 256
                        continue
                # CRC32 table heuristic: 256*4 bytes with non-zero entries
                if i + 256*4 <= L:
                    # quick sanity - not all zeros
                    some_nonzero = False
                    for k in range(0, 256*4, 4):
                        v = u32_le_from(bb, i+k)
                        if v is None:
                            break
                        if v != 0:
                            some_nonzero = True
                            break
                    if some_nonzero:
                        # report as possible CRC32 table (cheap check)
                        note(addr.add(i), "Memory", "Possible 256x4 CRC32 table (candidate)")
                        crc32_found += 1
                i += 1
            offset += chunk_len
    print("[*] Memory scan done: AES/%d perm/%d rcon/%d crc32/%d" % (aes_found, perm_found, rcon_found, crc32_found))
    return (aes_found, perm_found, rcon_found, crc32_found)

# Function level heuristics
def decompile_func_text(func, timeout=8):
    try:
        ifc = DecompInterface()
        ifc.openProgram(currentProgram)
        res = ifc.decompileFunction(func, timeout, ConsoleTaskMonitor())
        if not res.decompileCompleted():
            return None
        return res.getDecompiledFunction().getC()
    except Exception as e:
        return None

def scan_functions_for_patterns():
    print("[*] Scanning functions for RC4 / XTEA / KDF-like patterns...")
    funcs = fm.getFunctions(True)
    rc4_candidates = []
    xtea_candidates = []
    kdf_candidates = []
    total = 0
    for func in funcs:
        total += 1
        try:
            ctext = decompile_func_text(func, timeout=6)
            if ctext is None:
                continue
            low = ctext.lower()
            # RC4 KSA heuristic: for (i=0; i<256; ...) + mask + swap
            ksa_hit = False
            prga_hit = False
            if RE_KSA_LOOPT.search(low) and RE_KSA_MASK.search(low):
                # further check swap pattern or key modulo
                if RE_SWAP_TMP.search(low) or RE_KEY_MOD.search(low):
                    ksa_hit = True
            # PRGA heuristics
            if RE_PRGA_I.search(low) and (RE_PRGA_J.search(low) or RE_PRGA_OUT.search(low)):
                prga_hit = True
            if ksa_hit or prga_hit:
                msg = "RC4-like function: "
                if ksa_hit:
                    msg += "KSA-like "
                if prga_hit:
                    msg += "PRGA-like "
                note(func.getEntryPoint(), "Function", msg + "(heuristic)")
                rc4_candidates.append((func, ksa_hit, prga_hit, ctext))
            # XTEA/TEA ARX heuristics
            if RE_XTEA_ARX.search(low):
                note(func.getEntryPoint(), "Function", "XTEA/TEA-like ARX pattern (<<4/>>5 or delta constant)")
                xtea_candidates.append((func, ctext))
            # KDF-like detection: look for loops that mix key bytes or repeated rounds
            # Heuristic: loop with add/xor with an array 'key' or repeated iterations > 100
            kdf_hit = False
            # look for "key[...]" accesses combined with loops
            if "key[" in low and "for" in low:
                # further heuristic: look for '+' or '^' combining key bytes into accumulator
                if re.search(r'key\[.*\].*[\+\^]', low):
                    kdf_hit = True
            # also look for large-iteration loops (>= 100) - crude detection by numbers in code
            if re.search(r'for\s*\([^;]+;\s*[^;]*\b\d{3,}\b[^;]*;\s*[^)]+\)', low):
                kdf_hit = True
            if kdf_hit:
                note(func.getEntryPoint(), "Function", "KDF-like pattern (loop + key mixing)")
                kdf_candidates.append((func, ctext))
        except Exception as e:
            # ignore decompiler errors, continue
            pass
    print("[*] Function scan complete: checked %d functions" % total)
    return (rc4_candidates, xtea_candidates, kdf_candidates)

# Rc4 Key extraction ksa heuristics
def try_extract_key_from_rc4_ksa(func, decomp_text):
    """
    Heuristic: if decompiled KSA uses expression key[i % keylen] or reads from an array named 'key',
    attempt to find the data address referenced and read a small contiguous array as the key.
    Returns dict with 'key_addr','key_len','bytes' if successful.
    """
    low = decomp_text.lower()
    # find occurrences like key[...] or key[i % n]
    key_matches = re.findall(r'([a-z0-9_]+)\s*\[.*?i.*?\%.*?\]', low)
    # also try simple key[...] occurrences (no modulo)
    key_matches_simple = re.findall(r'([a-z0-9_]+)\s*\[.*?key', low)
    # prefer 'key' literal name if present
    candidates = []
    if "key[" in low:
        # try to extract the identifier used as key array: look for "<ident>["
        m = re.search(r'([a-z0-9_]+)\s*\[', low)
        if m:
            candidates.append(m.group(1))
    # add any matched tokens
    for t in key_matches:
        if t not in candidates:
            candidates.append(t)
    for t in key_matches_simple:
        if t not in candidates:
            candidates.append(t)

    # fallback: search for any small array references used in the function by pattern "arrayname + i"
    arr_refs = re.findall(r'([a-z0-9_]+)\s*\[\s*i\s*%?\s*', low)
    for t in arr_refs:
        if t not in candidates:
            candidates.append(t)

    # try to map candidate names to data addresses by scanning data near function or global symbols
    # The decompiler text may include absolute addresses like DAT_0000abcd - try to catch those
    dat_addrs = re.findall(r'dat_[0-9a-f]{4,}', decomp_text, re.IGNORECASE)
    # Convert DAT_xxx tokens into addresses via symbol table when possible
    # Build list of possible data addresses to test for being a key array
    key_arrays = []
    # Use explicit DAT_xxx tokens
    for token in dat_addrs:
        token_lower = token.lower()
        # attempt to resolve symbol to address
        try:
            sym = currentProgram.getSymbolTable().getSymbols(token_lower)
            for s in sym:
                addr = s.getAddress()
                if addr is not None:
                    key_arrays.append(addr)
        except:
            pass
    # Search for global labels that match candidate names
    for cand in candidates:
        try:
            syms = currentProgram.getSymbolTable().getSymbols(cand)
            for s in syms:
                addr = s.getAddress()
                if addr is not None:
                    key_arrays.append(addr)
        except:
            pass

    # If none found, try scanning near function for small arrays (heuristic)
    if len(key_arrays) == 0:
        func_body = func.getBody()
        start = func_body.getMinAddress()
        # scan forward a limited window for data references
        try:
            for off in range(0, 0x400, 4):
                a = start.add(off)
                # read a pointer-like value from program memory (word) and see if it points to bytes region
                try:
                    # Try reading a byte and next bytes to see plausible key
                    b0 = read_bytes(a, 1)
                    if b0 is None:
                        continue
                    # treat a as direct data array start candidate
                    key_arrays.append(a)
                    break
                except:
                    pass
        except Exception:
            pass

    # dedupe
    uniq = []
    for a in key_arrays:
        if a not in uniq:
            uniq.append(a)
    key_arrays = uniq

    # Test each candidate address for being a small key array: check lengths 1..MAX_KEY_BYTES and
    # verify that address is readable and values look plausible (non-zero or small)
    for addr in key_arrays:
        for keylen in range(MIN_KEY_BYTES, min(MAX_KEY_BYTES, 64)+1):  # try up to 64 bytes quickly
            try:
                bb = read_bytes(addr, keylen)
                if bb is None:
                    break
                # simple heuristic: not all zeros
                nonzero = False
                for b in bb:
                    if b != 0:
                        nonzero = True
                        break
                if not nonzero:
                    continue
                # looks plausible - return
                return {"key_addr": addr, "key_len": keylen, "bytes": bb}
            except:
                break
    return None

# Main analysis function
def analyze_all():
    start_time = time.time()
    # Memory scan
    (aes_cnt, perm_cnt, rcon_cnt, crc32_cnt) = scan_blocks_for_tables()

    # Function scan
    (rc4_candidates, xtea_candidates, kdf_candidates) = scan_functions_for_patterns()

    # Attempt key extraction for RC4 KSA candidates
    extracted_keys = []
    for (func, ksa, prga, decomp) in rc4_candidates:
        # only try extraction when KSA-like found
        if not ksa:
            continue
        try:
            res = try_extract_key_from_rc4_ksa(func, decomp)
            if res is not None:
                msg = "RC4 key candidate found at %s len=%d" % (res["key_addr"].toString(), res["key_len"])
                note(func.getEntryPoint(), "Key", msg)
                # print hex bytes
                hexstr = " ".join(["%02x" % (b,) for b in res["bytes"]])
                print("Extracted key bytes @ %s : %s" % (res["key_addr"].toString(), hexstr))
                extracted_keys.append((func, res))
        except Exception as e:
            print("Key extraction failed for %s: %s" % (func.getEntryPoint().toString(), str(e)))

    # XTEA/XOR/CRC notes already added during scan
    # Summarize
    elapsed = time.time() - start_time
    summary = []
    summary.append("Scan complete in %.2f seconds" % (elapsed,))
    summary.append("Memory: AES headers=%d, 256-perm=%d, Rcon=%d, CRC32-like=%d" % (aes_cnt, perm_cnt, rcon_cnt, crc32_cnt))
    summary.append("Functions: RC4 candidates=%d, XTEA-like=%d, KDF-like=%d" % (len(rc4_candidates), len(xtea_candidates), len(kdf_candidates)))
    if len(extracted_keys) > 0:
        summary.append("Extracted key candidates: %d" % len(extracted_keys))
    else:
        summary.append("Extracted key candidates: 0")
    # Print summary to console
    print("==== CRYPTO SCAN SUMMARY ====")
    for s in summary:
        print(s)
    print("Bookmarks added under category: %s" % (BOOKMARK_CATEGORY,))
    # Show popup with top lines
    popup = "\n".join(summary[:8])
    show_popup_text("Crypto Scan Summary", popup)
    return {
        "summary": summary,
        "rc4_candidates": rc4_candidates,
        "xtea_candidates": xtea_candidates,
        "kdf_candidates": kdf_candidates,
        "extracted_keys": extracted_keys
    }

def show_popup_text(title, txt):
    ta = JTextArea(txt, 20, 80)
    ta.setEditable(False)
    sp = JScrollPane(ta)
    JOptionPane.showMessageDialog(None, sp, title, JOptionPane.PLAIN_MESSAGE)

def main():
    try:
        res = analyze_all()
    except Exception as e:
        print("Scan failed: " + str(e))
        show_popup_text("Crypto Scan Error", "Scan failed: " + str(e))
        return
    # Optionally prompt to save extracted keys
    if len(res.get("extracted_keys", [])) > 0:
        # ask user if they want to save the first key
        try:
            choice = JOptionPane.showConfirmDialog(None, "Save extracted key candidates to file?", "Save Keys", JOptionPane.YES_NO_OPTION)
            if choice == JOptionPane.YES_OPTION:
                # write each extracted key to a file under ghidra_scripts folder
                out_base = askString("Output folder", "Enter output folder (absolute path)", "/tmp")
                if out_base is None or out_base.strip() == "":
                    out_base = "/tmp"
                idx = 0
                for (func, resk) in res["extracted_keys"]:
                    fname = out_base + "/extracted_key_%d.bin" % (idx,)
                    try:
                        f = open(fname, "wb")
                        f.write(bytes(resk["bytes"]))
                        f.close()
                        print("Saved key to " + fname)
                    except Exception as e:
                        print("Failed to save key " + fname + ": " + str(e))
                    idx += 1
                JOptionPane.showMessageDialog(None, "Saved keys (if possible) to folder: " + out_base)
        except Exception:
            pass

if __name__ == "__main__":
    main()

