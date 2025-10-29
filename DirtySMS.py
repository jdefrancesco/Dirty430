# DirtySMS 
# Find SMS related functionality via heuristics and SMS indicators.
#  - Global septet sweep across all memory 
#    to find packed GSM-7 text stored as packed septets with arbitrary bit alignment.
#  - Find candidate AT-SMS commands and SMS-related functions 
#@category DataComms
#@author J. DeFrancesco


from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from javax.swing import JOptionPane, JScrollPane, JTextArea

import re
import string

BOOKMARK_SMS = "COMMS_SMS"
BOOKMARK_UART = "COMMS_UART"
BOOKMARK_PDU = "COMMS_PDU"
BOOKMARK_PDU_DECODE = "COMMS_PDU_DECODE"

MAX_CHUNK = 0x10000
DECOMP_TIMEOUT = 5

# Septet sweep 
MIN_SEPTET_LEN = 8           # min septets to attempt decoding
MAX_SEPTET_LEN = 160         # max septets to attempt decoding
MIN_PRINTABLE_RATIO = 0.70   # threshold for marking decoded text as plausible
SWEEP_WINDOW_BYTES = 512     # sliding window size to try across binary 
SWEEP_STEP = 8               # jump step between start offsets to reduce noise (
MAX_CHUNK_SWEEP = 0x4000     # chunk size when reading memory for sweep

UART_NAMES = [
    "uca0txbuf", "uca1txbuf", "uca2txbuf",
    "ucb0txbuf", "ucb1txbuf", "ucb2txbuf",
    "txbuf"
]

SMS_CMDS = [
    "AT+CMGS", "AT+CMSS", "AT+CMGW", "AT+CMGR",
    "AT+CMGL", "AT+CMGD", "AT+CMEE", "AT+CMGF",
    "AT+CSMP", "AT+CPMS", "AT+CSCS"
]

# Various AT codes used for init 
GSM_INIT = [
    "AT+CPIN", "AT+CREG", "AT+CSQ", "AT+CGATT",
    "AT+CGDCONT", "AT+CGSN", "AT+CGMI", "AT+CGMM"
]
GSM_RESPONSES = [
    "+CMGS:", "+CMS ERROR:", "+CSQ:", "+CREG:", "+CME ERROR:"
]

RE_SHIFT_LEFT = re.compile(r'<<\s*([0-7])')
RE_SHIFT_RIGHT = re.compile(r'>>\s*([0-7])')
RE_MASK_7F = re.compile(r'&\s*0x?7f\b', re.IGNORECASE)
RE_HEX = re.compile(r'^[0-9A-Fa-f]+$')

#  GSM 03.38 Table
def build_gsm0338_tables():
    """Return (basic, extended) GSM 03 mapping tables."""

    basic = {
        0x00:'@',0x01:'\u00a3',0x02:'$',0x03:'\u00a5',0x04:'\u00e8',0x05:'\u00e9',
        0x06:'\u00f9',0x07:'\u00ec',0x08:'\u00f2',0x09:'\u00c7',0x0a:'\n',0x0b:'\u00d8',
        0x0c:'\u00f8',0x0d:'\r',0x0e:'\u00c5',0x0f:'\u00e5',
        0x10:'\u0394',0x11:'_',0x12:'\u03a6',0x13:'\u0393',0x14:'\u039b',0x15:'\u03a9',
        0x16:'\u03a0',0x17:'\u03a8',0x18:'\u03a3',0x19:'\u0398',0x1a:'\u039e',0x1b:'\x1b',
        0x1c:'\u00c6',0x1d:'\u00e6',0x1e:'\u00df',0x1f:'\u00c9',
        0x20:' ',0x21:'!',0x22:'"',0x23:'#',0x24:'\u00a4',0x25:'%',0x26:'&',0x27:"'",
        0x28:'(',0x29:')',0x2a:'*',0x2b:'+',0x2c:',',0x2d:'-',0x2e:'.',0x2f:'/',
        0x30:'0',0x31:'1',0x32:'2',0x33:'3',0x34:'4',0x35:'5',0x36:'6',0x37:'7',
        0x38:'8',0x39:'9',0x3a:':',0x3b:';',0x3c:'<',0x3d:'=',0x3e:'>',0x3f:'?',
        0x40:'\u00a1',0x41:'A',0x42:'B',0x43:'C',0x44:'D',0x45:'E',0x46:'F',0x47:'G',
        0x48:'H',0x49:'I',0x4a:'J',0x4b:'K',0x4c:'L',0x4d:'M',0x4e:'N',0x4f:'O',
        0x50:'P',0x51:'Q',0x52:'R',0x53:'S',0x54:'T',0x55:'U',0x56:'V',0x57:'W',
        0x58:'X',0x59:'Y',0x5a:'Z',0x5b:'\u00c4',0x5c:'\u00d6',0x5d:'\u00d1',0x5e:'\u00dc',0x5f:'\u00a7',
        0x60:'\u00bf',0x61:'a',0x62:'b',0x63:'c',0x64:'d',0x65:'e',0x66:'f',0x67:'g',
        0x68:'h',0x69:'i',0x6a:'j',0x6b:'k',0x6c:'l',0x6d:'m',0x6e:'n',0x6f:'o',
        0x70:'p',0x71:'q',0x72:'r',0x73:'s',0x74:'t',0x75:'u',0x76:'v',0x77:'w',
        0x78:'x',0x79:'y',0x7a:'z',0x7b:'\u00e4',0x7c:'\u00f6',0x7d:'\u00f1',0x7e:'\u00fc',0x7f:'\u00e0'
    }

    extended = {
        0x0a:'\u000c',   # form feed
        0x14:'^',
        0x28:'{',
        0x29:'}',
        0x2f:'\\',
        0x3c:'[',
        0x3d:'~',
        0x3e:']',
        0x40:'|',
        0x65:'\u20ac'    # Euro
    }
    return basic, extended

GSM_BASIC, GSM_EXT = build_gsm0338_tables()

memory = currentProgram.getMemory()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
bkm = currentProgram.getBookmarkManager()
symtab = currentProgram.getSymbolTable()
refmgr = currentProgram.getReferenceManager()

def note(addr, category, kind, msg):
    """Create bookmark and plate comment safely."""

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
    """Read n bytes from memory, return bytearray or None."""

    try:
        bb = bytearray(n)
        memory.getBytes(addr, bb)
        return bb
    except:
        return None

def find_all_defined_strings():
    """Return list of (string, address, length) for all defined string data."""

    out = []
    for data in listing.getDefinedData(True):
        try:
            if data.hasStringValue():
                s = str(data.getValue())
                a = data.getAddress()
                out.append((s, a, len(s)))
        except:
            pass
    return out

def search_strings_for(patterns, strings):
    """Find strings containing any pattern (case-insensitive)."""

    hits = []
    for (s, a, L) in strings:
        for pat in patterns:
            if pat.lower() in s.lower():
                hits.append((a, s))
                note(a, BOOKMARK_SMS, "AT_CMD", "AT literal: %s" % s)
                break
    return hits

def get_code_refs_to(addr):
    """Return list of code addresses that reference the address."""

    refs = refmgr.getReferencesTo(addr)
    res = []
    for r in refs:
        res.append(r.getFromAddress())
    return res

def find_uart_writes():
    """Scan all instructions for writes to known UART TX registers."""

    hits = []
    for func in fm.getFunctions(True):
        try:
            for ins in listing.getInstructions(func.getBody(), True):
                s = ins.toString().lower()
                for n in UART_NAMES:
                    if n in s:
                        note(ins.getAddress(), BOOKMARK_UART, "UART_TX", "UART TX: %s" % s)
                        hits.append((func, ins.getAddress(), n))
        except:
            pass
    return hits

def detect_gsm7_patterns(func):
    """Detect GSM 7-bit pack/unpack bit patterns and mask 0x7F, return score and hit addresses."""

    score = 0
    addrs = []
    try:
        for ins in listing.getInstructions(func.getBody(), True):
            s = ins.toString().lower()
            a = ins.getAddress()
            if RE_SHIFT_LEFT.search(s) and RE_SHIFT_RIGHT.search(s):
                score += 1
                addrs.append(a)
            if RE_MASK_7F.search(s):
                score += 1
                addrs.append(a)
            if ('<< 7' in s and '>> 1' in s) or ('<<7' in s and '>>1' in s):
                score += 2
                addrs.append(a)
    except:
        pass
    return score, addrs

def gsm7_unpack_octets(octets, septet_count):
    """Unpack GSM 7-bit from octet buffer into list of septet ints."""

    septets = []
    L = len(octets)
    for i in range(septet_count):
        bit_index = i * 7
        byte_index = bit_index // 8
        bit_offset = bit_index % 8
        low = 0
        high = 0
        if byte_index < L:
            low = (octets[byte_index] >> bit_offset) & 0xff
        if (byte_index + 1) < L:
            high = (octets[byte_index + 1] << (8 - bit_offset)) & 0xff
        septet = (low | high) & 0x7f
        septets.append(septet)
    return septets

def gsm7338_map_septets_to_text(septets):
    """Map septets through GSM 03.38 basic/extended tables to text."""

    out = []
    i = 0
    while i < len(septets):
        s = septets[i]
        if s == 0x1b:
            if i + 1 < len(septets):
                nxt = septets[i + 1]
                ch = GSM_EXT.get(nxt)
                if ch is None:
                    ch = '?'
                out.append(ch)
                i += 2
                continue
            else:
                out.append('?')
                i += 1
                continue
        ch = GSM_BASIC.get(s)
        if ch is None:
            if 32 <= s <= 126:
                ch = chr(s)
            else:
                ch = '?'
        out.append(ch)
        i += 1
    return ''.join(out)

def printable_ratio(txt):
    """Compute printable ASCII ratio."""

    if not txt:
        return 0.0
    count = 0
    for c in txt:
        if c in string.printable and c != '\t':
            count += 1
    return float(count) / float(len(txt))

VERBOSE = False  # set True for full septet sweep 
def sweep_septets_global():
    """Perform a global brute-force septet sweep across initialized memory blocks.

    Tries all 7 bit alignments and slides windows, attempting to unpack and
    detect high-ratio printable GSM7 text. Bookmarks plausible findings.
    """

    findings = []
    for blk in memory.getBlocks():
        if not blk.isInitialized():
            continue
        start = blk.getStart()
        size = blk.getSize()
        off = 0
        while off < size:
            chunk = MAX_CHUNK_SWEEP if (size - off) > MAX_CHUNK_SWEEP else (size - off)
            base = start.add(off)
            bb = read_bytes(base, chunk)
            if bb is None:
                off += chunk
                continue
            L = len(bb)
            pos = 0
            while pos + 1 < L:
                for bit_shift in range(0, 7):
                    max_sept_possible = ((L - pos) * 8 - bit_shift) // 7
                    if max_sept_possible < MIN_SEPTET_LEN:
                        continue
                    max_sept = min(MAX_SEPTET_LEN, max_sept_possible)
                    trial_lengths = []
                    trial_lengths.append(max_sept)
                    mid = (max_sept + MIN_SEPTET_LEN) // 2
                    if mid != max_sept and mid >= MIN_SEPTET_LEN:
                        trial_lengths.append(mid)
                    if MIN_SEPTET_LEN not in trial_lengths:
                        trial_lengths.append(MIN_SEPTET_LEN)

                    for sept_len in trial_lengths:
                        bits_needed = sept_len * 7 + bit_shift
                        octets_needed = (bits_needed + 7) // 8
                        if pos + octets_needed > L:
                            continue

                        window = bb[pos:pos + octets_needed]
                        val = 0
                        for i in range(len(window) - 1, -1, -1):
                            val = (val << 8) | window[i]
                        val_shifted = val >> bit_shift
                        adjusted = []
                        for i in range(0, octets_needed):
                            adjusted.append(val_shifted & 0xff)
                            val_shifted >>= 8
                        adjusted = bytearray(adjusted)

                        septs = gsm7_unpack_octets(adjusted, sept_len)
                        txt = gsm7338_map_septets_to_text(septs)
                        if not txt or len(set(txt)) < 5:
                            continue

                        pr = printable_ratio(txt)
                        if pr < MIN_PRINTABLE_RATIO:
                            continue

                        if not re.search(r'[A-Za-z0-9+ ]', txt):
                            continue

                        addr = base.add(pos)
                        text_preview = txt[:40] + ("..." if len(txt) > 40 else "")
                        msg = "Septet sweep: bit_shift=%d septets=%d printable=%.2f text=%s" % (
                            bit_shift, sept_len, pr, text_preview)

                        note(addr, BOOKMARK_PDU_DECODE, "SEPTET_SWEEP", msg)
                        findings.append((addr, bit_shift, sept_len, pr, txt))

                        if VERBOSE:
                            print("DEBUG bit_shift=%d sept_len=%d pr=%.2f text=%s"
                                  % (bit_shift, sept_len, pr, text_preview))

                        pos += octets_needed
                        break
                pos += SWEEP_STEP
            off += chunk
    return findings


# PDU parsing helpers from previous script: semi-octet swap, decode number, simple PDU parse.
def semi_octet_swap(hex_digits):
    """Swap semi-octets in a hex string like '123456' -> '214365'."""

    out = []
    for i in range(0, len(hex_digits), 2):
        if i + 1 < len(hex_digits):
            out.append(hex_digits[i + 1])
            out.append(hex_digits[i])
        else:
            out.append('F')
            out.append(hex_digits[i])
    return ''.join(out)

def decode_number_from_toa_addr(addr_hex, toa_hex, digits_len):
    """Decode BCD semi-octet number from address field."""

    swapped = semi_octet_swap(addr_hex)
    digits = swapped[:digits_len]
    digits = digits.replace('F', '')
    if toa_hex.startswith('91'):
        return '+' + digits
    return digits

# Attempt at minimal PSU parsing.. Handles basics for now.
def pdu_try_parse_hex(hexstr_bytes):
    """Attempt to parse minimal PDU hexstring (returns dict or None)."""

    try:
        hexstr = ''.join(chr(c) for c in hexstr_bytes)
    except:
        return None
    hexstr = hexstr.strip()
    if len(hexstr) < 20 or len(hexstr) % 2 != 0:
        return None
    if not RE_HEX.match(hexstr):
        return None

    try:
        pdu = bytearray.fromhex(hexstr)
    except:
        return None

    i = [0]
    def get_oct():
        if i[0] >= len(pdu):
            return None
        v = pdu[i[0]]
        i[0]     += 1
        return v

    smsc_len = get_oct()
    if smsc_len is None:
        return None
    smsc_end = 1 + smsc_len
    if smsc_end > len(pdu):
        return None
    toa = get_oct()
    if toa is None:
        return None
    i = smsc_end
    fo = get_oct()
    if fo is None:
        return None
    mti = fo & 0x03
    udhi = (fo & 0x40) != 0
    parsed = {"mti": mti, "udhi": udhi, "ud_septets": None, "da": None, "pid": None, "dcs": None, "ud": None, "ud_text": None}
    if mti == 1:
        mr = get_oct()
        da_len = get_oct()
        toa_da = get_oct()
        addr_octets = (da_len + 1) // 2
        da_raw = pdu[i:i + addr_octets]
        i += addr_octets
        da_hex = ''.join('%02X' % b for b in da_raw)
        parsed["da"] = decode_number_from_toa_addr(da_hex, '%02X' % toa_da, da_len)
        parsed["pid"] = get_oct()
        parsed["dcs"] = get_oct()
        if i >= len(pdu):
            return parsed
        udl = get_oct()
        if udl is None:
            return parsed
        ud = pdu[i:]
        parsed["ud"] = ud
        parsed["ud_septets"] = udl
        septets = gsm7_unpack_octets(ud, udl)
        txt = gsm7338_map_septets_to_text(septets)
        pr = printable_ratio(txt)
        if pr >= 0.5:
            parsed["ud_text"] = txt
        return parsed
    elif mti == 0:
        oa_len = get_oct()
        toa_oa = get_oct()
        addr_octets = (oa_len + 1) // 2
        oa_raw = pdu[i:i + addr_octets]
        i += addr_octets
        oa_hex = ''.join('%02X' % b for b in oa_raw)
        parsed["da"] = decode_number_from_toa_addr(oa_hex, '%02X' % toa_oa, oa_len)
        parsed["pid"] = get_oct()
        parsed["dcs"] = get_oct()
        i += 7
        if i >= len(pdu):
            return parsed
        udl = get_oct()
        if udl is None:
            return parsed
        ud = pdu[i:]
        parsed["ud"] = ud
        parsed["ud_septets"] = udl
        septets = gsm7_unpack_octets(ud, udl)
        txt = gsm7338_map_septets_to_text(septets)
        pr = printable_ratio(txt)
        if pr >= 0.5:
            parsed["ud_text"] = txt
        return parsed
    else:
        return parsed

def find_pdu_hex_near(func, window_bytes):
    """Scan defined strings near function for plausible PDU hex strings and parse them."""

    results = []
    strings = find_all_defined_strings()
    ep = func.getEntryPoint()
    for (s, a, L) in strings:
        try:
            if memory.getBlock(a) != memory.getBlock(ep):
                continue
        except:
            continue
        dist = abs(a.subtract(ep))
        if dist > window_bytes:
            continue
        s_stripped = s.strip()
        if len(s_stripped) >= 20 and len(s_stripped) % 2 == 0 and RE_HEX.match(s_stripped):
            parsed = pdu_try_parse_hex(bytearray(s_stripped.encode('ascii', 'ignore')))
            if parsed is not None:
                results.append((a, s_stripped, parsed))
    return results

def correlate_and_run_sweep():
    """Run AT string detection, UART detection, PDU parse, GSM7 function heuristic, and global sweep."""

    strings = find_all_defined_strings()
    at_hits = search_strings_for(SMS_CMDS + GSM_INIT + GSM_RESPONSES, strings)

    fmgr = fm
    at_ref_funcs = {}
    for (addr, s) in at_hits:
        refs = get_code_refs_to(addr)
        for ra in refs:
            f = fmgr.getFunctionContaining(ra)
            if f:
                at_ref_funcs.setdefault(f.getName(), set()).add(f)

    uart_hits = find_uart_writes()

    flagged = []
    for f in fmgr.getFunctions(True):
        score, bit_addrs = detect_gsm7_patterns(f)
        has_uart = False
        for (ff, a, n) in uart_hits:
            if ff == f:
                has_uart = True
                break
        pdu_near = find_pdu_hex_near(f, SWEEP_WINDOW_BYTES)

        decoded_near = []
        if score > 0:
            decoded_near = find_candidate_gsm7_windows_near_func(f, SWEEP_WINDOW_BYTES)

        ep = f.getEntryPoint()
        if score > 0:
            note(ep, BOOKMARK_PDU, "PDU_FUNC", "GSM7 heuristic score=%d" % score)

        for (a, hexs, parsed) in pdu_near:
            note(a, BOOKMARK_PDU, "PDU_HEX", "PDU hex near %s" % f.getName())
            if parsed and parsed.get("ud_text"):
                note(a, BOOKMARK_PDU_DECODE, "PDU_UD", "PDU UD: %s" % parsed.get("ud_text")[:120])

        for (addr, septs, pr, txt) in decoded_near:
            note(addr, BOOKMARK_PDU_DECODE, "PDU_DECODE", "Decoded %d septets printable=%.2f: %s" % (septs, pr, txt[:120]))

        f_in_at = f.getName() in at_ref_funcs
        if f_in_at and has_uart and (score > 0 or len(pdu_near) > 0 or len(decoded_near) > 0):
            note(ep, BOOKMARK_SMS, "SMS_TX_FUNC", "Likely SMS TX: AT refs + UART + GSM7/PDU")
            flagged.append((f, score, has_uart, len(pdu_near), len(decoded_near)))

    # now run global septet sweep which is heavier
    sweep_results = sweep_septets_global()

    return {
        "at_literals": len(at_hits),
        "uart_sites": len(uart_hits),
        "flagged_funcs": len(flagged),
        "sweep_hits": len(sweep_results)
    }

def find_candidate_gsm7_windows_near_func(func, window_bytes):
    """Wrapper to reuse existing near-function decode logic from prior code."""

    results = []
    ep = func.getEntryPoint()
    blk = memory.getBlock(ep)
    if blk is None:
        return results
    blk_start = blk.getStart()
    try:
        off_rel = ep.subtract(blk_start)
    except:
        return results
    start_off = int(off_rel) - window_bytes
    if start_off < 0:
        start_off = 0
    end_off = int(off_rel) + window_bytes
    max_span = int(blk.getEnd().subtract(blk_start))
    if end_off > max_span:
        end_off = max_span
    base = blk_start.add(start_off)
    span = end_off - start_off
    raw = read_bytes(base, span)
    if raw is None:
        return results
    max_sept = min(MAX_SEPTET_LEN, (len(raw) * 8) // 7)
    for sept_len in range(MIN_SEPTET_LEN, max_sept + 1):
        need_oct = (sept_len * 7 + 7) // 8
        if need_oct > len(raw):
            break
        for off in range(0, len(raw) - need_oct + 1):
            window = raw[off:off + need_oct]
            septs = gsm7_unpack_octets(window, sept_len)
            txt = gsm7338_map_septets_to_text(septs)
            pr = printable_ratio(txt)
            if pr >= MIN_PRINTABLE_RATIO:
                addr = base.add(off)
                results.append((addr, sept_len, pr, txt))
                off += need_oct
    return results

VERBOSE = False

def main():
    """Main entry point sweep."""

    print("==== DirtySMS Starting ====")
    res = correlate_and_run_sweep()

    lines = []
    lines.append("DirtySMS Finished. Summary:")
    lines.append("AT/GSM literals found: %d" % res.get("at_literals", 0))
    lines.append("UART TX write sites: %d" % res.get("uart_sites", 0))
    lines.append("Likely SMS TX functions: %d" % res.get("flagged_funcs", 0))
    lines.append("Septet sweep hits: %d" % res.get("sweep_hits", 0))

    ta = JTextArea("\n".join(lines), 16, 80)
    ta.setEditable(False)
    JOptionPane.showMessageDialog(None, JScrollPane(ta), "DirtySMS Summary", JOptionPane.PLAIN_MESSAGE)

    for l in lines:
        print(l)
    print("==== DirtySMS done ====")

if __name__ == "__main__":
    main()