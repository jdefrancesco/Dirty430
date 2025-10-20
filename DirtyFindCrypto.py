# -*- coding: utf-8 -*-
# DirtyFindCrypto.py
#
# Fast crypto constant finder for Ghidra (MSP430, embedded firmware, etc.)
# FIXED: bytearray -> Java signed byte[] conversion (no more OverflowError!)
#
# Usage: Run inside Ghidra (Script Manager). Labels, bookmarks, and comments are auto-added.
# Optional CSV export can be enabled below.
#
# Author: J. DeFrancesco (improved by ChatGPT)


EXPORT_CSV = False
CSV_FILENAME = "DirtyFindCrypto_hits.csv"
COMMENT_PREFIX = "[Dirty430 CryptoFinder]"
LABEL_FORCE_PRIMARY = True


try:
    from ghidra.program.model.mem import MemoryAccessException
    from ghidra.program.model.data import ByteDataType, DWordDataType, ArrayDataType
    from ghidra.util.task import TaskMonitor
    from ghidra.program.flatapi import FlatProgramAPI
    import jarray
except:
    print("Warning: Ghidra imports failed. This script must run in Ghidra.")
    pass



def bytes_from_list_u8(lst):
    return bytearray([x & 0xff for x in lst])

def u32_le_bytes(v):
    v = v & 0xffffffff
    return bytearray([v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff])

def dwords_to_le_bytes(dlist):
    out = bytearray()
    for v in dlist:
        out.extend(u32_le_bytes(v))
    return out

def fmt_addr(addr):
    try: return str(addr)
    except: return "<addr>"

def define_array_at(addr, total_len_bytes, dtype):
    try:
        elem_len = dtype.getLength()
        if elem_len <= 0:
            return False
        count = max(1, total_len_bytes // elem_len)
        arr = ArrayDataType(dtype, count, elem_len)
        createData(addr, arr)
        return True
    except:
        return False

def add_crypto_bookmark(addr, short_text, long_text=None):
    try:
        createBookmark(addr, "Info", "CRYPTO", short_text)
    except:
        pass
    try:
        if long_text:
            setPlateComment(addr, long_text)
        else:
            setPlateComment(addr, short_text)
    except:
        pass

def make_label(addr, label):
    try:
        createLabel(addr, label, LABEL_FORCE_PRIMARY)
    except:
        try:
            createLabel(addr, label, False)
        except:
            pass

#

class CryptoFinder(object):
    def __init__(self, program):
        self.prog = program
        self.api = FlatProgramAPI(program)
        self.mem = program.getMemory()
        self.minA = self.mem.getMinAddress()
        self.maxA = self.mem.getMaxAddress()
        self.report = []

    def _to_java_bytes(self, py_bytes):
        """Convert Python bytes/bytearray/list → Java signed byte[] (-128..127)"""
        if isinstance(py_bytes, basestring):
            seq = [ord(c) & 0xff for c in py_bytes]
        else:
            seq = [int(x) & 0xff for x in py_bytes]
        signed = [b if b < 0x80 else b - 0x100 for b in seq]
        return jarray.array(signed, 'b')

    def _find_all(self, seq_bytes):
        """Use Ghidra Memory.findBytes() with Java byte[] pattern."""
        pattern = self._to_java_bytes(seq_bytes)
        start = self.minA
        while True:
            hit = self.mem.findBytes(start, self.maxA, pattern, None, True, TaskMonitor.DUMMY)
            if hit is None:
                break
            yield hit
            try:
                start = hit.add(1)
            except:
                break

    def scan_and_label(self, seq_bytes, label_prefix, dtype, define_len=None, describe=None):
        hits = 0
        tlen = define_len if define_len is not None else len(seq_bytes)
        for i, addr in enumerate(self._find_all(seq_bytes)):
            label = "%s_%d" % (label_prefix, i)
            make_label(addr, label)
            define_array_at(addr, tlen, dtype)
            short = "%s %s @ %s" % (COMMENT_PREFIX, label_prefix, fmt_addr(addr))
            long = "%s found %s\nlen=%d bytes" % (COMMENT_PREFIX, label_prefix, tlen)
            if describe:
                long += "\n" + describe
            add_crypto_bookmark(addr, short, long)
            self.report.append((label, addr))
            hits += 1
        return hits

    def find_large_blocks(self, min_size):
        blocks = []
        addr = self.minA
        in_block = False
        block_start = None
        block_len = 0

        while addr and addr <= self.maxA:
            try:
                self.mem.getByte(addr)
                readable = True
            except MemoryAccessException:
                readable = False

            if not readable:
                if in_block and block_len >= min_size:
                    blocks.append((block_start, block_len))
                in_block = False
                block_start = None
                block_len = 0
            else:
                if not in_block:
                    in_block = True
                    block_start = addr
                    block_len = 1
                else:
                    block_len += 1

            if addr.equals(self.maxA):
                if in_block and block_len >= min_size:
                    blocks.append((block_start, block_len))
                break
            addr = addr.next()

        return blocks



def main():
    print("=== [D430 CryptoFinder] ===")
    cf = CryptoFinder(currentProgram)

    AES_SBOX = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76
    ] + [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0]*8

    AES_INV_SBOX = [0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38]*32
    AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
    SHA1_H = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    SHA256_K = [0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5]
    MD5_T = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee]
    BLOWP = [0x243F6A88,0x85A308D3,0x13198A2E,0x03707344]
    TEA_DELTA = u32_le_bytes(0x9E3779B9)

    AES_SBOX_B     = bytes_from_list_u8(AES_SBOX)
    AES_INV_SBOX_B = bytes_from_list_u8(AES_INV_SBOX)
    AES_RCON_B     = bytes_from_list_u8(AES_RCON)
    SHA1_H_B       = dwords_to_le_bytes(SHA1_H)
    SHA256_K_B     = dwords_to_le_bytes(SHA256_K)
    MD5_T_B        = dwords_to_le_bytes(MD5_T)
    BLOWP_B        = dwords_to_le_bytes(BLOWP)

    hits  = cf.scan_and_label(AES_SBOX_B,     "CRYPTO_AES_SBOX",     ByteDataType(), len(AES_SBOX_B))
    hits += cf.scan_and_label(AES_INV_SBOX_B, "CRYPTO_AES_INV_SBOX", ByteDataType(), len(AES_INV_SBOX_B))
    hits += cf.scan_and_label(AES_RCON_B,     "CRYPTO_AES_RCON",     ByteDataType(), len(AES_RCON))
    hits += cf.scan_and_label(SHA1_H_B,       "CRYPTO_SHA1_H",       DWordDataType(), len(SHA1_H)*4)
    hits += cf.scan_and_label(SHA256_K_B,     "CRYPTO_SHA256_K",     DWordDataType(), len(SHA256_K)*4)
    hits += cf.scan_and_label(MD5_T_B,        "CRYPTO_MD5_T",        DWordDataType(), len(MD5_T)*4)
    hits += cf.scan_and_label(BLOWP_B,        "CRYPTO_BLOWFISH_P",   DWordDataType(), len(BLOWP)*4)

    tea_hits = list(cf._find_all(TEA_DELTA))
    for i, a in enumerate(tea_hits):
        lbl = "CRYPTO_TEA_DELTA_%d" % i
        make_label(a, lbl)
        define_array_at(a, 4, DWordDataType())
        add_crypto_bookmark(a, COMMENT_PREFIX + " TEA_DELTA", "TEA delta constant")
        cf.report.append((lbl, a))

    blocks = cf.find_large_blocks(176)
    for i,(addr,size) in enumerate(blocks):
        if size >= 1024:
            lbl = "POTENTIAL_AES_TTABLE_%d_%dB" % (i,size)
            make_label(addr,lbl)
            define_array_at(addr, min(size,4096), ByteDataType())
            cf.report.append((lbl,addr))
        else:
            lbl = "CRYPTO_LARGE_BLOCK_%d_%dB" % (i,size)
            make_label(addr,lbl)
            define_array_at(addr, min(size,1024), ByteDataType())
            cf.report.append((lbl,addr))

    print("\n=== Results ===")
    for lbl, addr in cf.report:
        print("  %-35s @ %s" % (lbl, fmt_addr(addr)))
    print("Total labels: ", len(cf.report))

if __name__ == "__main__":
    main()
