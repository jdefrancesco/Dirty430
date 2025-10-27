# DirtyStack.py
#
# MSP430X stack behavior analyzer:
# - Detect PUSH/POP, CALL/CALLA, frame setup using SUB SP
# - Only check stack alignment problems in PROLOGUES (initial frame setup)
# - Warn if SUB #odd, SP or PUSH creates misaligned stack
# - Bookmark stack behavior but leave unrelated code alone
#
#@category StackAnalysis
#@author J. DeFrancesco

from ghidra.program.model.listing import CodeUnit
from javax.swing import JOptionPane, JScrollPane, JTextArea

import re, time

BOOKMARK_STACK = "STACK"

RE_PUSH       = re.compile(r'\bpush(\.w|\s)\s+(r\d+|sr|pc|sp|#[^,]+)', re.IGNORECASE)
RE_SUB_SP     = re.compile(r'\bsub(\.w|\s)\s+#(0x[0-9a-f]+|\d+)\s*,\s*sp\b', re.IGNORECASE)
RE_ADD_SP     = re.compile(r'\badd(\.w|\s)\s+#(0x[0-9a-f]+|\d+)\s*,\s*sp\b', re.IGNORECASE)
RE_CALL20     = re.compile(r'\bcalla\b', re.IGNORECASE)
RE_CALL16     = re.compile(r'\bcall\b', re.IGNORECASE)
RE_RET20      = re.compile(r'\breta\b', re.IGNORECASE)
RE_RET16      = re.compile(r'\bret\b', re.IGNORECASE)

memory  = currentProgram.getMemory()
listing = currentProgram.getListing()
bkm     = currentProgram.getBookmarkManager()

def note(addr, kind, msg):
    """
    Create a stack bookmark and comment.

    :param addr: Address to annotate
    :param kind: Type of stack event (PUSH, FRAME_ALLOC, etc.)
    :param msg: Description
    """

    try:
        bkm.setBookmark(addr, BOOKMARK_STACK, kind, msg)
    except:
        pass
    try:
        listing.setComment(addr, CodeUnit.PLATE_COMMENT, "[%s] %s" % (BOOKMARK_STACK, msg))
    except:
        pass
    try:
        print("%s | %s @ %s : %s" % (BOOKMARK_STACK, kind, addr.toString(), msg))
    except:
        pass

def _parse_imm(v):
    """
    Parse immediate string as hex or decimal.

    :param v: ex: '0x10' or '16'
    :return: integer or None
    """

    try:
        if v.startswith("0x") or v.startswith("0X"):
            return int(v, 16)
        return int(v)
    except:
        return None

def analyze_function_stack(func):
    """
    Only analyze prologue-style stack setup:
    - PUSH (saves registers)
    - SUB #imm, SP (alloc frame)
    - If imm is odd, mark potential misalignment
    """

    try:
        instrs = listing.getInstructions(func.getBody(), True)
    except:
        return None

    prologue_seen = False
    odd_misaligned = False
    pushes = 0
    locals_size = 0

    for ins in instrs:
        s = ins.toString().lower()
        a = ins.getAddress()

        if RE_PUSH.search(s):
            pushes += 1
            note(a, "PUSH", "Register pushed (SP -= 2)")
            prologue_seen = True
            continue

        m = RE_SUB_SP.search(s)
        if m:
            imm = _parse_imm(m.group(2))
            if imm is not None:
                locals_size += imm
                if imm % 2 != 0:
                    odd_misaligned = True
                    note(a, "FRAME_WARN", "SUB #%d,SP (odd stack alloc, misaligned)" % imm)
                else:
                    note(a, "FRAME_ALLOC", "SUB #%d,SP" % imm)
            prologue_seen = True
            continue

        if prologue_seen:
            break

    return {"pushes": pushes, "locals": locals_size, "misaligned": odd_misaligned}

def main():
    start = time.time()
    fm = currentProgram.getFunctionManager()
    summaries = []

    for func in fm.getFunctions(True):
        res = analyze_function_stack(func)
        summaries.append((func, res))

    misaligned_count = sum(1 for (_,r) in summaries if r and r["misaligned"])
    func_count = len(summaries)

    elapsed = time.time() - start
    lines = []
    lines.append("DirtyStack complete in %.2f s" % elapsed)
    lines.append("Functions scanned: %d" % func_count)
    lines.append("Functions with misaligned stack in prologue: %d" % misaligned_count)

    ta = JTextArea("\n".join(lines), 15, 60)
    ta.setEditable(False)
    JOptionPane.showMessageDialog(None, JScrollPane(ta), "Stack Analysis Summary", JOptionPane.PLAIN_MESSAGE)

if __name__ == "__main__":
    main()
