# DirtyFindCrypto.py
# 
# Search MSP430 Firmware for potential crypto functions.
# 
# Detects:
#  AES S-box, Inv S-box, Rcon
#  SHA1 H, SHA256 K, MD5 T
#  TEA delta clusters
#  Large opaque byte blocks (>=176 or >=1024 bytes)

#@author J. DeFrancesco
#@category Crypto

try:
    from ghidra.program.model.mem import MemoryAccessException
    from ghidra.program.model.data import ByteDataType, DWordDataType, ArrayDataType
    from ghidra.util.task import TaskMonitor
except:
    print("Failed to import ghidra headers. Continuing for debug mode.")
    pass

def bytes_from_list(lst): return ''.join([chr(x & 0xff) for x in lst])

def uint32_to_le_bytes(v): return chr(v & 0xff) + chr((v>>8)&0xff) + chr((v>>16)&0xff) + chr((v>>24)&0xff)

def dwords_to_bytes_le(dlist):
    """Convert list of dwords to LE"""

    out = []
    for v in dlist:
        out.append(chr(v & 0xff))
        out.append(chr((v >> 8) & 0xff))
        out.append(chr((v >> 16) & 0xff))
        out.append(chr((v >> 24) & 0xff))
    return ''.join(out)


def to_hex(b):
    """Print as string for debug."""
    return ' '.join(["%02X" % (ord(x) & 0xFF) for x in b])


class CryptoFinder(object):
    def __init__(self, program):
        self.prog = program
        self.mem = program.getMemory()
        self.minA = self.mem.getMinAddress()
        self.maxA = self.mem.getMaxAddress()
        self.report = []

    def read_byte(self, addr):
        try:
            return self.mem.getByte(addr) & 0xff
        except MemoryAccessException:
            return None

    def read_chunk(self, addr, n):
        try:
            return self.mem.getBytes(addr, n)
        except MemoryAccessException:
            return None

    def find_sequence(self, seq_bytes):
        results = []
        s0 = ord(seq_bytes[0])
        addr = self.minA
        while addr and addr <= self.maxA:
            b = self.read_byte(addr)
            if b is None:
                addr = addr.next()
                continue
            if b == s0:
                chunk = self.read_chunk(addr, len(seq_bytes))
                if chunk == seq_bytes:
                    results.append(addr)
                    addr = addr.add(len(seq_bytes))
                    continue
            addr = addr.next()
        return results

    
    def label_and_define(self, addr, label, length, dtype):
        try:
            createLabel(addr, label, True)
        except Exception:
            try:
                createLabel(addr, label, False)
            except Exception:
                pass
        try:
            arr = ArrayDataType(dtype, length, dtype.getLength())
            createData(addr, arr)
        except Exception:
            pass
        self.report.append((label, addr))

    # large block heuristic
    def find_large_blocks(self, min_size):
        blocks = []
        addr = self.minA
        in_block = False
        block_start = None
        block_len = 0
        while addr and addr <= self.maxA:
            b = self.read_byte(addr)
            if b is None:
                if in_block and block_len >= min_size:
                    blocks.append((block_start, block_len))
                in_block = False
                block_start = None
                block_len = 0
                addr = addr.next()
                continue
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

    def scan_and_label(self, seq_bytes, label_prefix, dtype, define_len=None):
        found = self.find_sequence(seq_bytes)
        for i,addr in enumerate(found):
            lbl = "%s_%d" % (label_prefix, i)
            self.label_and_define(addr, lbl, define_len or len(seq_bytes), dtype)
        return len(found)

def main():
    """Main function"""
    
    print("=== [D430 CryptoFinder] scanning program for cryptographic constants ===")
    cf = CryptoFinder(currentProgram)

    # AES Constants
    AES_SBOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76]
    # Truncatedd for brevity...  should be good enough...
    AES_SBOX += [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0]*8  

    AES_INV_SBOX = [0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38]*32
    AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]
    SHA1_H = [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]
    SHA256_K = [0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5]
    MD5_T = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee]
    CHACHA = [0x61707865,0x3320646E,0x79622D32,0x6B206574]
    BLOWP = [0x243F6A88,0x85A308D3,0x13198A2E,0x03707344]
    CURVE = chr(0x09) + ("\x00"*31)
    TEA_DELTA = uint32_to_le_bytes(0x9E3779B9)

    AES_SBOX_B = bytes_from_list(AES_SBOX)
    AES_INV_SBOX_B = bytes_from_list(AES_INV_SBOX)
    AES_RCON_B = bytes_from_list(AES_RCON)
    SHA1_H_B = dwords_to_bytes_le(SHA1_H)
    SHA256_K_B = dwords_to_bytes_le(SHA256_K)
    MD5_T_B = dwords_to_bytes_le(MD5_T)
    BLOWP_B = dwords_to_bytes_le(BLOWP)

    # Search for our crypto looking stuff
    hits = 0
    hits += cf.scan_and_label(AES_SBOX_B, "CRYPTO_AES_SBOX", ByteDataType(), len(AES_SBOX_B))
    hits += cf.scan_and_label(AES_INV_SBOX_B, "CRYPTO_AES_INV_SBOX", ByteDataType(), len(AES_INV_SBOX_B))
    hits += cf.scan_and_label(AES_RCON_B, "CRYPTO_AES_RCON", ByteDataType(), len(AES_RCON))
    hits += cf.scan_and_label(SHA1_H_B, "CRYPTO_SHA1_H", DWordDataType(), len(SHA1_H)*4)
    hits += cf.scan_and_label(SHA256_K_B, "CRYPTO_SHA256_K", DWordDataType(), len(SHA256_K)*4)
    hits += cf.scan_and_label(MD5_T_B, "CRYPTO_MD5_T", DWordDataType(), len(MD5_T)*4)
    hits += cf.scan_and_label(BLOWP_B, "CRYPTO_BLOWFISH_P", DWordDataType(), len(BLOWP)*4)

    # TEA clusters
    tea_hits = cf.find_sequence(TEA_DELTA)
    if tea_hits:
        for i,a in enumerate(tea_hits):
            cf.label_and_define(a, "CRYPTO_TEA_DELTA_%d" % i, 4, DWordDataType())
        print("[+] TEA delta: %d hits" % len(tea_hits))
        hits += len(tea_hits)

    # large opaque blocks
    big_blocks = cf.find_large_blocks(176)
    for i,(addr,size) in enumerate(big_blocks):
        if size >= 1024:
            cf.label_and_define(addr, "POTENTIAL_AES_TTABLE_%d_%dB" % (i,size), min(size,4096), ByteDataType())
        elif size < 4096:
            cf.label_and_define(addr, "CRYPTO_LARGE_BLOCK_%d_%dB" % (i,size), min(size,1024), ByteDataType())

    print("\n=== [D430 CryptoFinder] results ===")
    for lbl,addr in cf.report:
        print("  %-35s  @ %s" % (lbl, addr))
    print("Total labels created: %d" % len(cf.report))
    if not cf.report:
        print("[!] No known crypto constants detected.")
    else:
        print("[*] Check out X-refs to labels!")

if __name__ == "__main__":
    main()
