# -*- coding: utf-8 -*-
# DirtyDecompiler.py

# Performs multiple cleanups on MSP430 decompiled output:
# NOTE: Alot of this was adapted from an old IDA Script I had written.
#       Still debugging heavy before I merge into Dirty430.py. One Ghidra
#       Module  will be much simpler to get on machines probably...

#  - Arithmetic simplification (mul/div). No mul/div unit.
#  - Bitmask macro cleanup
#  - Switch recovery
#  - Struct detection
#  - Constant folding
#  - Adjusting any weird stack behavior

# XXX: Will be merged into Dirty430.py single script after tested.

#@author J. DeFrancesco
#@category MSP430 Decompiler Cleanup

import re

from ghidra.util import Msg # pyright: ignore[reportMissingModuleSource]
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnit


# Different builds keep it either in clang or decompiler package...
try:
    from ghidra.app.decompiler.clang import ClangTokenGroup, ClangToken
    HAVE_CLANG = True
except Exception:
    try:
        from ghidra.app.decompiler import ClangTokenGroup, ClangToken  #
        HAVE_CLANG = True
    except Exception:
        ClangTokenGroup = None
        HAVE_CLANG = False

try:
    from ghidra.program.flatapi import FlatProgramAPI
except Exception:
    FlatProgramAPI = None



# ---- Conext management ----

# This are for keeping context import safe.
PROGRAM = None
ADDRESS = None
MONITOR = None


def set_ctx(program=None, address=None, monitor=None):
    """Initialize context when called from the REPL or wrapper.
       If args are None, try to pull from __main__ (REPL/script env)."""

    import __main__
    global PROGRAM, ADDRESS, MONITOR

    if program is None:
        program = getattr(__main__, 'currentProgram', None)
    if address is None:
        address = getattr(__main__, 'currentAddress', None)
    if monitor is None:
        monitor = getattr(__main__, 'monitor', None)
    if program is None:
        raise RuntimeError("DirtyDecompiler.set_ctx: supply program=currentProgram or run as a Ghidra script.")
    PROGRAM, ADDRESS, MONITOR = program, address, monitor

def _ensure_ctx():
    """Call at the start of any function that touches PROGRAM/ADDRESS/MONITOR."""
    if PROGRAM is None:
        set_ctx()  

# ---- End context management ----


# Debug verbosity
VERBOSE = True
# Global to hold the current Clang markup root
_CCODE_ROOT = None


# ----- HELPERS. When we merge the components we won't need this anymore.
def fmt_addr(a):
    """Format an address or int as 0xXXXXXXXX cause it annoys me."""

    return "0x%X" % _addr_int(a)


def _addr_int(a):
    """Return integer offset for either an int/long or a Ghidra Address-like object."""

    if a is None:
        return 0

    # Ghidra Address objects have getOffset / getUnsignedOffset
    if hasattr(a, 'getOffset'):
        try:
            return int(a.getOffset())
        except Exception:
            pass
    try:
        return int(a)
    except Exception:
        return 0


def _log(msg, kind='info', always=False):
    """Internal logging wrapper: emits via Msg and also prints for the script console..."""

    if not VERBOSE and not always:
        # Still show final summary lines (they use always=True) but skip noisy items.
        return
    if kind == 'warn':
        Msg.warn(None, msg)
    elif kind == 'error':
        Msg.error(None, msg)
    else:
        Msg.info(None, msg)
    try:
        print(msg)
    except Exception:
        pass


def _replace(tokens, addr, text):
    """Wrapper around. Will refactor later..."""
    return replace_tokens(tokens, addr, text)


def _flatten_clang_tokens(root):
    """Return a flat list of leaf ClangToken from a ClangTokenGroup tree."""

    out = []
    stack = [root]
    while stack:
        n = stack.pop()
        # Groups have children; tokens don’t.
        try:
            cnt = n.numChildren()
        except Exception:
            cnt = 0
        if cnt > 0:
            for i in range(cnt - 1, -1, -1):
                stack.append(n.Child(i))
        else:
            # Keep only real tokens (not punctuation groups etc.)
            if 'ClangToken' in type(n).__name__:
                out.append(n)
    return out


def _addr_contains(node, addr):
    try:
        a0 = node.getMinAddress()
        a1 = node.getMaxAddress()
        return a0 is not None and a1 is not None and a0.compareTo(addr) <= 0 and a1.compareTo(addr) >= 0
    except Exception:
        return False


def _find_enclosing_group(root, addr):
    """Return the smallest ClangTokenGroup whose address range contains addr."""

    best = None
    stack = [root]
    while stack:
        n = stack.pop()
        if isinstance(n, ClangTokenGroup) and _addr_contains(n, addr):
            best = n  # candidate
            try:
                for i in range(n.numChildren()-1, -1, -1):
                    stack.append(n.Child(i))
            except Exception:
                pass
    return best


# ----- Core Functions 

def get_decompiled_function(func, program=None, timeout=60):
    """Return DecompileResults for func. Works when imported if set_ctx() was called."""
    
    if program is None:
        _ensure_ctx()
        program = PROGRAM
    
    ifc = DecompInterface()

    try:
        opts = ifc.getOptions()
        opts.setParameterIdEnabled(True)
        ifc.setOptions(opts)
    except Exception:
        pass

    ifc.openProgram(program)

    _log("[D430] decompiling helper invoked on %s..." % func.getName())
    return ifc.decompileFunction(func, timeout, ConsoleTaskMonitor())


def decompile(func, program=None, timeout=60):
    """This call initializes new decompiler process. Only needs to be called when first ran """

    # Call decompiler function...
    res = get_decompiled_function(func, program=program, timeout=timeout)
    if not res or not res.decompileCompleted():
        return None, None, []

    hf = res.getHighFunction()

    # Collect our tokens and ensure we can walk/rewrite them.
    tokens = []
    if HAVE_CLANG:
        root = res.getCCodeMarkup()  # ClangTokenGroup tree
        if root is not None:
            tokens = _flatten_clang_tokens(root)
    else:
        _log("DirtyDecompiler: Clang token API not available; token rewrites disabled.", 'warn', always=True)

    _log("decomp: got %d tokens for %s" % (len(tokens), func.getName()))
    return res, hf, tokens
 

def replace_tokens(tokens, start_addr, new_text):
    """Replace text at a statement corresponding to start_addr.
    
    1. Try an exact leaf-token match.
    2. Fallback: rewrite the smallest enclosing ClangTokenGroup that spans the address.
    """
    
    # Exact leaf match
    for tok in tokens:
        if not hasattr(tok, "getMinAddress"):
            continue
        try:
            if tok.getMinAddress() == start_addr:
                parent = None
                try: parent = tok.Parent()
                except Exception: pass
                if parent and hasattr(parent, "removeChildren") and hasattr(parent, "addText"):
                    parent.removeChildren()
                    parent.addText(new_text)
                    # Yay, return now.
                    return True
        except Exception:
            pass

    # Enclosing-group fallback
    root = globals().get('_CCODE_ROOT')
    if root is not None:
        grp = _find_enclosing_group(root, start_addr)

        if grp and hasattr(grp, "removeChildren") and hasattr(grp, "addText"):
            try:
                grp.removeChildren()
                grp.addText(new_text)
                return True
            except Exception as e:
                _log("replace_tokens fallback failed: %s" % e, "warn")

    # No luck
    _log("replace_tokens: failed to find token/group at %s" % fmt_addr(start_addr), "warn", always=True)
    return False


def simplify_arithmetic(high_func, tokens):
    """Replace repeated-addition loops with multiply op."""

    for block in high_func.getBasicBlocks():
        ops = [op for op in block.getIterator()]

        # Look for basic blocks that use repeated addition/sub heuristic.
        add_ops = [op for op in ops if op.getOpcode() == PcodeOp.INT_ADD]
        sub_ops = [op for op in ops if op.getOpcode() == PcodeOp.INT_SUB]

        if len(add_ops) == 1 and len(sub_ops) == 1:
            addr = block.getStart()
            # Provide more readable C op. subs..
            if replace_tokens(tokens, addr, "sum = counter * constant; // simplified"):
                _log("[arithmetic] Simplified loop at %s " % fmt_addr(addr))

    _log("[arithmetic] Done")
    return


def bitmask_macros(high_func, tokens):
    """Convert reg |= / &= constants into macros for clarity.. 
    
    A lot of bit mask ops take place for things like bit banging over GPIO lines
    or masking parts of address.
    """

    # Simple and might not catch everything but we will try
    for block in high_func.getBasicBlocks():
        ops = [op for op in block.getIterator()]
        for op in ops:
            if op.getOpcode() in (PcodeOp.INT_AND, PcodeOp.INT_OR):
                input_count = op.getNumInputs() if hasattr(op, "getNumInputs") else op.getInputCount()
                out = op.getOutput()
                inputs = [op.getInput(i) for i in range(input_count)]

                if len(inputs) == 2 and inputs[1].isConstant():
                    const_val = inputs[1].getOffset()

                    if op.getOpcode() == PcodeOp.INT_OR:
                        # macro = f"SET_BITS({out.getHigh().getName()}, 0x{const_val:X})"
                        # Keep forgetting no f strings yet...
                        macro = "SET_BITS({}".format(out.getHigh().getName()) + " ,0x{:X}".format(const_val)
                    else:
                        macro = "CLEAR_BITS({}".format(out.getHigh().getName()) + " ,0x{:X}".format(const_val)
                    
                    if replace_tokens(tokens, op.getSeqnum().getTarget(), macro):
                        _log("[bitmask] Rewrote at %s "  % op.getSeqnum().getTarget())
                    else:
                        _log("[bitmask] No rewrite at %s" % op.getSeqnum().getTarget(), "warn")

    _log("[bitmask] Done") 
    return


def constant_folding(high_func, tokens):
    """Replace sequences like x = 0; x += y; with x = y;
    
    
    You'd think they do this already but no?? It doesn't seem to work all time
    time for some reason but that might be a configuration thing.
    """

    for block in high_func.getBasicBlocks():
        ops = [op for op in block.getIterator()]
        if len(ops) >= 2:
            # Get first and second operators
            first, second = ops[0], ops[1]
            first_input_count = first.getNumInputs() if hasattr(first, "getNumInputs") else first.getInputCount()
            second_input_count = second.getNumInputs() if hasattr(second, "getNumInputs") else second.getInputCount()

            if (first.getOpcode() == PcodeOp.COPY and first_input_count >= 1 and first.getInput(0).isConstant() and
                second.getOpcode() == PcodeOp.INT_ADD and second_input_count >= 1 and second.getInput(0) == first.getOutput()):

                addr = first.getSeqnum().getTarget()

                if replace_tokens(tokens, addr, "x = y; // const-folded"):
                    _log("[ConstFold] Folded at %s" %  fmt_addr(addr))

    _log("[constfold] Done")
    return


def memset_replace(high_func, tokens):
    """MSP430 yields weird 20 bit mem accesses that look like this in Ghidra:
    
    *(undefined2 *)((long)(int3)uVar1 - 2U & 0xffff) =
    *(undefined2 *)((ulong)(puVar5 + 1) & 0xffff);

    These usually occur inside a loop which generally might mean they are simply
    memset() zero like functions. We will use some heuristics to suggest if this is seen.

    if our hints variable hits a certain threshold I haven't determined quite yet
    we will suggest it as a candidate for memset() zeroing replacement. 

    We can probably make this more general later.
    """

    hints = 0
    for tok in tokens:
        s = str(tok)
        if "*(" in s and "= 0" in s:
            try:
                parent = tok.Parent()
            except Exception:
                parent = None
            if parent:
                try:
                    parent.addComment("dirty430: memset(buffer, 0, len) candidate")
                    hints += 1
                except Exception:
                    pass
    if hints:
        _log("dirty430: memset hints %d" % hints)

    _log("[memset] Done")
    return


def struct_recovery(high_func, tokens):
    """Group sequential memory addresses with different offsets signals possible struct.
    
    Consistent offsets normally mean arrays. These are super rough heuristics but generally
    work well enough.
    """

    addr_list = []
    for block in high_func.getBasicBlocks():
        for op in [op for op in block.getIterator()]:
            if op.getOpcode() == PcodeOp.LOAD:
                base = op.getInput(1)
                if base and base.isAddress():
                    addr_list.append(base.getAddress())


    addr_list.sort()
    for i in range(1, len(addr_list)):
        if int(addr_list[i].getOffset()) - int(addr_list[i-1].getOffset()) == 2:
            # Mark with comment.
            replace_tokens(tokens, addr_list[i-1], "// struct field sequence detected")
            _log("[Struct] Fields near %s " % fmt_addr(addr_list[i-1]))

    _log("[struct] Done")
    return

            
def switch_table_hint(high_func, tokens):
    """switch_table_hint suggests the replacement of switch to table.

    Table lookups occur a lot with various functions including crypto functions
    which might make idenitfy them a bit more clear.
    """

    collapsed = 0
    for bb in high_func.getBasicBlocks():
        ops = [op for op in bb.getIterator()]
        consts = []
        target = None

        for op in ops:
            input_count = op.getNumInputs() if hasattr(op, "getNumInputs") else op.getInputCount()
            if op.getOpcode() == PcodeOp.COPY and input_count == 1 and op.getInput(0).isConstant():
                consts.append(op.getInput(0).getOffset())
                if op.getOutput(): 
                    target = op.getOutput().getHigh().getName()

        if target and len(consts) >= 3:
            # Make C table construct.
            # These are constants of a possible table in hex.
            # arr_elements = ", ".join(f"0x{v:X}" for v in consts)
            # arr_elements = ", ".join("0x%X" % v for v in consts)
            # text = "static const uint16_t dirty430_tbl[] = \{ {} \};\n".format(arr_elements) +  "{} = dirty430_tbl[...]; ".format(target)
            arr_elements = ", ".join("0x%X" % v for v in consts)
            text = "static const uint16_t dirty430_tbl[] = {{ {0} }};\n{1} = dirty430_tbl[/* idx */]; ".format(arr_elements, target)

            if  replace_tokens(tokens, bb.getStart(), text):
                collapsed += 1
                _log("[D430] Created table.")
            else:
                _log("[D430] Skipping switch collapse")

    if collapsed: 
        _log("[D430] switch lookup has been collapsed: %s" % collapsed)

    
    _log("[switch] Done")
    return


def pass_resume_points(high_func, tokens):
    """ Detects stores to the fixed local slot (SP-4) with a code-like constant and:
    You see this pattern when dealing with state-machine like constructs sometimes..

      - creates a label at that address (if plausible),
      - rewrites the store as 'resume_pc = 0xXXXX; // resume label',
      - tries to rename the stack var to 'resume_pc'.
    """
    
    try:
        fpa = FlatProgramAPI(PROGRAM, MONITOR or ConsoleTaskMonitor())
    except TypeError:
        fpa = FlatProgramAPI(program=PROGRAM)
        
    mem = PROGRAM.getMemory()
    labeled = 0
    rewrote = 0


    ## TODO(REFACTOR)

    # Match: *(undefined4 *)(<something> - 4) = 0x1234;
    _PAT_RESUME = re.compile(r"\*\s*\(\s*undefined4\s*\*\s*\)\s*\(\s*[^)]+-\s*4\s*\)\s*=\s*0x([0-9A-Fa-f]+)\s*;")
 

    def _mk_addr(off):
        return PROGRAM.getAddressFactory().getDefaultAddressSpace().getAddress(off)

    # Try to rename the stack symbol at -4 into resume_pc (best effort)
    try:
        symmap = high_func.getLocalSymbolMap()
        for s in symmap.getSymbols():
            # crude heuristic: first undefined4 on stack near -4
            if "undefined4" in str(s.getDataType()):
                storage = s.getStorage()
                # storage dump is noisy; skip hard test and just rename the first candidate
                try:
                    if s.getName().startswith("local_") or "unaff" in s.getName():
                        s.rename("resume_pc")
                        break
                except Exception:
                    pass
    except Exception:
        pass

    for tok in tokens:
        s = str(tok)
        if "undefined4" not in s:
            continue
        m = _PAT_RESUME.search(s)
        if not m:
            continue
        val = int(m.group(1), 16)
        addr = _mk_addr(val & 0xFFFF) 
        # label if looks like valid code
        try:
            if mem.contains(addr):
                try:
                    fpa.createLabel(addr, "L_resume_%04X" % (val & 0xFFFF), True)
                    labeled += 1
                except Exception:
                    pass
        except Exception:
            pass

        # rewrite the assignment text
        line = "resume_pc = 0x%X; // Dirty430: resume point" % val
        if replace_tokens(tokens, tok.getMinAddress(), line):
            rewrote += 1

    if labeled or rewrote:
        _log("decomp: resume points labeled=%d, rewritten=%d" % (labeled, rewrote))


def pass_fix_msp430x_20bit_ptr(tokens):
    """Rewrites MSP430X 20-bit effective address construction into a more verbose
    form thats easier to recognize (subjectively to me anyhow..)

    Example in -> puVar4 = (undefined2 *)(long)(int3)(unaff_R3 + (int3)puVar4 & 0xfffff);
    Example out -> puVar4 = (uint16_t *)(((uint32_t)unaff_R3 + (uint32_t)(uintptr_t)puVar4) & 0xFFFFF); // dirty430 20-bit
    -> puVar4 = 0x0FFFF (20 bit addr)

    TODO: REMOVE OR HANDLE ELSEWHERE
    """

    def _group_text(node):
        # best-effort stringify the node subtree
        try:
            n = node.numChildren()
            parts = []
            for i in range(n):
                parts.append(str(node.Child(i)))
            return "".join(parts)
        except:
            return str(node)

    # Matches:  LHS = (undefined2 *)(long)(int3)(BASE + (int3)PTR & 0xfffff);
    _PAT_20BIT = re.compile(
        r"""(?P<lhs>\w+)\s*=\s*
            \(\s*undefined2\s*\*\s*\)\s*
            \(\s*long\s*\)\s*
            \(\s*int3\s*\)\s*
            \(\s*(?P<base>\w+)\s*\+\s*
            \(\s*int3\s*\)\s*(?P<ptr>\w+)\s*&\s*0x[fF]{5}\s*\)
            \s*;?""",
        re.X
    )

    fixes = 0
    for tok in tokens:
        s = str(tok)
        # Fast filter: only bother if this token looks like the mask
        if "0xfffff" not in s and "0xFFFFF" not in s:
            continue
        parent = tok.Parent()
        if not isinstance(parent, ClangTokenGroup):
            continue

        text = _group_text(parent)
        m = _PAT_20BIT.search(text)
        if not m:
            continue

        lhs  = m.group("lhs")
        base = m.group("base")
        ptr  = m.group("ptr")

        new_line = "{lhs} = (uint16_t *)(((uint32_t){base} + (uint32_t)(uintptr_t){ptr}) & 0xFFFFF); ".format(lhs=lhs, base=base, ptr=ptr) 
        

        # Replace at this node's address (same trick as your other passes)
        if _replace(tokens, tok.getMinAddress(), new_line):
            fixes += 1

    if fixes:
        _log("decomp: 20-bit ptr wrap simplified {fixes} site(s)".format(fixes=fixes))


def clean_function(func):
    """Cleans up a single function's decompiled output."""

    _log("[D430] Attempting to clean %s" % func.getName())

    res, high_func, tokens = decompile(func)
    if not res:
        _log("decomp: failed %s" % func.getName(), 'warn', always=True)
        return
    simplify_arithmetic(high_func, tokens)
    bitmask_macros(high_func, tokens)
    constant_folding(high_func, tokens)
    switch_table_hint(high_func, tokens)
    struct_recovery(high_func, tokens)
    memset_replace(high_func, tokens)
    pass_resume_points(high_func, tokens)
    pass_fix_msp430x_20bit_ptr(tokens)

    _log("decomp: cleaned %s" % func.getName())


def run_current():
    _ensure_ctx()

    func = getFunctionContaining(ADDRESS)
    if not func:
        _log("[D430]: No function at current address.", 'warn', always=True)
        return
    clean_function(func)


def run_all():
    """Cleans all functions in the current program."""

    _ensure_ctx()

    fm = PROGRAM.getFunctionManager()
    it = fm.getFunctions(True)

    i = 0
    while it.hasNext():
        clean_function(it.next())
        i += 1
    _log("[D430]: cleaned %d function(s)" % i, always=True)


def main():
    """Main
    
    Entry point when run as a script. This deals specifically with cleaning
    up decompilation output caused by messy MSP430 code generation using Ghidra.
    """

    _log("[D430] Dirty Decompiler script starting...", always=True)

    # Initialize context if needed.
    set_ctx()

    # Run only on current function.
    run_current()

if __name__ == "__main__":
    main()

