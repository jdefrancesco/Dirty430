# -*- coding: utf-8 -*-
# DirtyDecompiler.py 

# @author J. DeFrancesco
# @category MSP430

from ghidra.util import Msg
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import ClangTokenGroup, ClangToken
from javax.swing import JOptionPane, JScrollPane, JTextArea
import re

def fmt_addr(a):
    return "0x%X" % _addr_int(a)

def _addr_int(a):
    if a is None:
        return 0
    if hasattr(a, 'getOffset'):
        try:
            return int(a.getOffset())
        except:
            pass
    try:
        return int(a)
    except:
        return 0

def get_decompiled_function(func, program=None, timeout=60):
    ifc = DecompInterface()
    opts = ifc.getOptions()
    try:
        opts.setParameterIdEnabled(True)
    except:
        pass
    ifc.setOptions(opts)
    ifc.openProgram(program)
    print("[D430] decompiling %s..." % func.getName())
    return ifc.decompileFunction(func, timeout, ConsoleTaskMonitor())

def decompile(func, program=None, timeout=60):
    res = get_decompiled_function(func, program=currentProgram, timeout=timeout)
    if not res or not res.decompileCompleted():
        return None, None, [], None

    hf = res.getHighFunction()
    root = res.getCCodeMarkup()
    tokens = _flatten_clang_tokens(root) if root else []
    print("decomp: got %d tokens for %s" % (len(tokens), func.getName()))
    return res, hf, tokens, root

def _flatten_clang_tokens(root):
    out = []
    stack = [root]
    while stack:
        n = stack.pop()
        try:
            cnt = n.numChildren()
        except:
            cnt = 0
        if cnt > 0:
            for i in range(cnt - 1, -1, -1):
                stack.append(n.Child(i))
        else:
            if 'ClangToken' in type(n).__name__:
                out.append(n)
    return out

def bitmask_macros(high_func, tokens, root):
    for block in high_func.getBasicBlocks():
        for op in block.getIterator():
            if op.getOpcode() in (PcodeOp.INT_AND, PcodeOp.INT_OR):
                inputs = [op.getInput(i) for i in range(op.getNumInputs())]
                out = op.getOutput()
                if len(inputs) == 2 and inputs[1].isConstant():
                    const_val = inputs[1].getOffset()
                    macro = ("SET_BITS({}," if op.getOpcode() == PcodeOp.INT_OR else "CLEAR_BITS({}") \
                             .format(out.getHigh().getName()) + ",0x{:X})".format(const_val)

                    if replace_tokens(tokens, op.getSeqnum().getTarget(), macro, root):
                        print("[bitmask] Rewrote at %s" % op.getSeqnum().getTarget())
                    else:
                        # Fail silent, not big deal for now
                        continue

    print("[bitmask] Done")

def replace_tokens(tokens, start_addr, new_text, root):
    for tok in tokens:
        if hasattr(tok, "getMinAddress") and tok.getMinAddress() == start_addr:
            parent = None
            try: parent = tok.Parent()
            except: pass
            if parent and hasattr(parent, "removeChildren") and hasattr(parent, "addText"):
                parent.removeChildren()
                parent.addText(new_text)
                return True

    if root:
        grp = _find_enclosing_group(root, start_addr)
        if grp and hasattr(grp, "removeChildren") and hasattr(grp, "addText"):
            try:
                grp.removeChildren()
                grp.addText(new_text)
                return True
            except Exception as e:
                # Fail silently 
                pass

    # Fail silent here.
    return False

def _addr_contains(node, addr):
    try:
        a0 = node.getMinAddress()
        a1 = node.getMaxAddress()
        return a0 is not None and a1 is not None and a0.compareTo(addr) <= 0 and a1.compareTo(addr) >= 0
    except:
        return False

def _find_enclosing_group(root, addr):
    best = None
    stack = [root]
    while stack:
        n = stack.pop()
        if isinstance(n, ClangTokenGroup) and _addr_contains(n, addr):
            best = n
        try:
            for i in range(n.numChildren() - 1, -1, -1):
                stack.append(n.Child(i))
        except:
            pass
    return best

def clean_function(func):
    print("[D430] Cleaning %s" % func.getName())
    res, high_func, tokens, root = decompile(func)
    if not res:
        print("fail decomp")
        return
    bitmask_macros(high_func, tokens, root)

def run_current():
    func = getFunctionContaining(currentAddress)
    if not func:
        print("[D430]: No function at current address.")
        return
    clean_function(func)

def clean_clutter():
    func = getFunctionContaining(currentAddress)
    if not func:
        print("No function at current address.")
        return
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    result = ifc.decompileFunction(func, 30, ConsoleTaskMonitor())
    if not result.decompileCompleted():
        print("Decompilation failed.")
        return
    original = result.getDecompiledFunction().getC()
    cleaned = original
    text = JTextArea(cleaned, 40, 80)
    text.setEditable(False)
    scroll = JScrollPane(text)
    JOptionPane.showMessageDialog(None, scroll, "Clean Decompiled Output", JOptionPane.PLAIN_MESSAGE)

 # Regexes to detect lines to remove entirely
RE_STACK_ASSIGN     = re.compile(r'^\s*\*\([^)]*\)\s*\([^)]*uVar\d+[^)]*\)\s*=\s*[^;]+;\s*$')
RE_UNDEFINED_WRITE  = re.compile(r'^\s*\*\(undefined[124]\s*\*\)\s*\([^)]*\)\s*=\s*\d+;\s*$')
RE_USELESS_UVAR     = re.compile(r'^\s*uVar\d+\s*=\s*\(ulong\)\(int3\)\(.*\);\s*$')

def aggressive_clean(code):
    cleaned_lines = []

    for line in code.splitlines():
        s = line.strip()
        # Remove entire lines that match known junk patterns
        if RE_STACK_ASSIGN.match(s):
            continue
        if RE_UNDEFINED_WRITE.match(s):
            continue
        if RE_USELESS_UVAR.match(s):
            continue

        # Now apply *inline* cleanup but keep original formatting
        line = re.sub(r'\(ulong\)\(int3\)', '', line)
        line = re.sub(r'\(int3\)', '', line)
        line = re.sub(r'\(uint3\)', '', line)
        line = re.sub(r'\(undefined[0-9]\)', '', line)

        # Remove & 0xffff or & 0xfffff (masked address junk)
        line = re.sub(r'&\s*0x?fffff?', '', line)

        cleaned_lines.append(line)

    # Do NOT collapse whitespace. Just return with original line structure.
    return "\n".join(cleaned_lines)

   
def clean_clutter():
    func = getFunctionContaining(currentAddress)
    if func is None:
        print("No function here.")
        return

    # Decompile
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(func, 30, ConsoleTaskMonitor())
    if not res.decompileCompleted():
        print("Failed to decompile.")
        return

    original = res.getDecompiledFunction().getC()
    cleaned = aggressive_clean(original)

    # Show popup
    text = JTextArea(cleaned, 40, 80)
    text.setEditable(False)
    scroll = JScrollPane(text)
    JOptionPane.showMessageDialog(None, scroll, "Aggressively Cleaned Decompiler Output", JOptionPane.PLAIN_MESSAGE)


def main():
    print("[D430] Dirty Decompiler script starting...")
    run_current()
    clean_clutter()

if __name__ == "__main__":
    main()
