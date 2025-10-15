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


    """
    Detect memcpy-like bursts that copy 16-bit words into a 20-bit wrapped dest:
      STORE:  *(uint16_t*)((long)(int3)IDX - 2U? & 0xffff) = *(uint16_t*)((ulong)(SRC [+ k]) & 0xffff);
    with nearby evidence of 20-bit advancement of IDX via some BASE (often unaff_R3):
      ADV:    IDX = BASE + IDX & 0xfffff;
              IDX = BASE + (int3)PTR & 0xfffff;
              PTR = (T*)(long)(int3)(BASE + IDX & 0xfffff);
    We don't require strict STORE/ADV alternation: we just count STOREs and confirm at least
    one ADV for the same IDX within a sliding window.

    Writes a summary EOL comment on the first STORE and short tags on following lines.
    """

    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
    import re

    # --- helpers ---
    def _flatten_groups(root):
        try:
            from ghidra.app.decompiler import ClangTokenGroup
        except Exception:
            try:
                from ghidra.app.decompiler.clang import ClangTokenGroup
            except Exception:
                ClangTokenGroup = None
        out = []
        if root is None or ClangTokenGroup is None:
            return out
        st = [root]
        while st:
            g = st.pop()
            if isinstance(g, ClangTokenGroup):
                try:
                    parts = []
                    for i in range(g.numChildren()):
                        parts.append(str(g.Child(i)))
                    txt = "".join(parts)
                except Exception:
                    txt = str(g)
                try:
                    a = g.getMinAddress()
                except Exception:
                    a = None
                out.append((txt, a))
                for i in range(g.numChildren()-1, -1, -1):
                    st.append(g.Child(i))
        return out

    def _norm_stmt(s):
        # normalize whitespace, strip noisy do-block braces/prefixes
        s = s.strip()
        if s.startswith("do {"):
            s = s[3:].strip()
        if s.endswith("}"):
            s = s[:-1].strip()
        return s

    def _add_eol(addr, text):
        if addr is None:
            return
        try:
            listing = (PROGRAM or currentProgram).getListing()
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                return
            old = cu.getComment(CodeUnit.EOL_COMMENT)
            if old:
                if text in old:
                    return
                cu.setComment(CodeUnit.EOL_COMMENT, old + " | " + text)
            else:
                cu.setComment(CodeUnit.EOL_COMMENT, text)
        except Exception:
            pass

    def _bm(addr, cat, msg):
        try: createBookmark(addr, cat, msg)
        except: pass

    # --- fresh decompile snapshot ---
    ifc = DecompInterface()
    ifc.openProgram(PROGRAM or currentProgram)
    func = high_func.getFunction()
    dr = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())
    if not dr or not dr.decompileCompleted():
        _log("[memcpy20R] decompile failed; pass skipped", "warn")
        return 0

    # split groups into semi-statements
    items = []
    for txt, a in _flatten_groups(dr.getCCodeMarkup()):
        for p in txt.split(';'):
            p = p.strip()
            if p:
                items.append((_norm_stmt(p) + ';', a))

    # --- regexes (loose) ---
    # 16-bit copy store into (int3)IDX - 2 ... & 0xffff
    RE_STORE = re.compile(r"""
        ^\*\s*\(\s*(?:undefined2|u?short|uint16_t)\s*\*\s*\)\s*
        \(\s*(?:long\s*\)\s*)?(?:\(?\s*int3\s*\)?\s*)?
        (?P<idx>\w+)\s*(?:[-+]\s*0*2[Uu]?)?\s*[^)]*?&\s*0x[fF]{4}\s*\)\s*=\s*
        \*\s*\(\s*(?:undefined2|u?short|uint16_t)\s*\*\s*\)\s*
        \(\s*(?:u?long|u?int32_t|ulong)\s*\)\s*
        \(\s*(?P<src>\w+)(?:\s*\+\s*(?P<off>0x[0-9A-Fa-f]+|\d+))?\s*\)\s*&\s*0x[fF]{4}\s*;$
    """, re.X)

    # Any evidence of 20-bit advancement for the same idx
    RE_ADV_A = re.compile(r"""^(?P<idx>\w+)\s*=\s*(?P<base>\w+)\s*\+\s*(?P=idx)\s*&\s*0x[fF]{5}\s*;$""")
    RE_ADV_B = re.compile(r"""^(?P<idx>\w+)\s*=\s*(?P<base>\w+)\s*\+\s*\(\s*int3\s*\)\s*\w+\s*&\s*0x[fF]{5}\s*;$""")
    RE_ADV_C = re.compile(r"""^\w+\s*=\s*\(.*\)\s*\(\s*long\s*\)\s*\(\s*int3\s*\)\s*\(\s*(?P<base>\w+)\s*\+\s*(?P<idx>\w+)\s*&\s*0x[fF]{5}\s*\)\s*;$""")

    # Debug capture
    dbg_store_like, dbg_adv_like = [], []

    # --- scan & group runs by destination idx ---
    n = len(items)
    used = [False] * n
    annotated_pairs = 0

    i = 0
    while i < n:
        t, a = items[i]
        m = RE_STORE.match(t[:-1].strip())
        if not m:
            # near-miss debug
            if "*(" in t and "& 0x" in t and "= *(" in t:
                if len(dbg_store_like) < dump_limit:
                    dbg_store_like.append((a, t))
            i += 1
            continue

        idx = m.group("idx")
        src = m.group("src")

        # look ahead to collect more STOREs that keep same idx (allow interleaved noise)
        run_idxs = [i]
        j = i + 1
        adv_seen = False
        base_seen = None

        steps = 0
        while j < n and steps < lookahead:
            tt, aa = items[j]
            s = tt[:-1].strip()

            # more stores?
            mm = RE_STORE.match(s)
            if mm and mm.group("idx") == idx and mm.group("src") == src:
                run_idxs.append(j)

            # any adv forms?
            ma = RE_ADV_A.match(s)
            mb = RE_ADV_B.match(s)
            mc = RE_ADV_C.match(s)
            if ma and ma.group("idx") == idx:
                adv_seen = True
                base_seen = base_seen or ma.group("base")
            elif mb and re.search(r"\b" + re.escape(idx) + r"\b", s):
                adv_seen = True
                base_seen = base_seen or mb.group("base")
            elif mc and mc.group("idx") == idx:
                adv_seen = True
                base_seen = base_seen or mc.group("base")

            j += 1
            steps += 1

        # Only annotate if enough stores and we saw 20-bit advance for this idx
        store_count = len(run_idxs)
        if store_count >= min_stores and adv_seen:
            head_addr = items[run_idxs[0]][1]
            summary = "Dirty430: memcpy16_20bit(dst=%s, src=%s, words=%d)%s" % (
                idx, src, store_count, (" via %s" % base_seen) if base_seen else ""
            )
            _add_eol(head_addr, summary)
            _bm(head_addr, "Dirty430", "memcpy16_20bit x%d" % store_count)

            # short tags on each store in the run
            for k in run_idxs[1:]:
                _add_eol(items[k][1], "Dirty430: memcpy run")
            annotated_pairs += store_count

            # skip past this window to avoid duplicate annotations
            i = run_idxs[-1] + 1
        else:
            # debug ADV-like
            if not adv_seen and debug:
                # collect a few ADV-like strings around here
                for w in range(i, min(n, i + 10)):
                    ss, aa = items[w]
                    if "& 0x" in ss and "+" in ss and ("0xfffff" in ss or "int3" in ss):
                        if len(dbg_adv_like) < dump_limit:
                            dbg_adv_like.append((aa, ss))
            i += 1

    if debug:
        _log("[memcpy20R] stores annotated: %d" % annotated_pairs)
        if dbg_store_like:
            _log("[memcpy20R][debug] STORE-like (first %d):" % len(dbg_store_like))
            for a, line in dbg_store_like:
                off = ("0x%X" % a.getOffset()) if a else "<?>"
                _log("  %s :: %s" % (off, line))
        if dbg_adv_like:
            _log("[memcpy20R][debug] ADV-like (first %d):" % len(dbg_adv_like))
            for a, line in dbg_adv_like:
                off = ("0x%X" % a.getOffset()) if a else "<?>"
                _log("  %s :: %s" % (off, line))

    return annotated_pairs



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
    """
    Detects stores to a fixed local stack slot (SP-3 or SP-4) with a code-like
    constant and:
      - creates a label at that address (if plausible),
      - rewrites the store as 'resume_pc = 0xXXXXX; // resume label' (20-bit OK),
      - tries to rename the stack var to 'resume_pc'.

    Accepts MSP430X 20-bit encodings (undefined3 / int3) and classic 32-bit.
    """

    # FlatProgramAPI for labeling
    try:
        fpa = FlatProgramAPI(PROGRAM, MONITOR or ConsoleTaskMonitor())
    except TypeError:
        fpa = FlatProgramAPI(program=PROGRAM)

    mem = PROGRAM.getMemory()
    af  = PROGRAM.getAddressFactory()
    dspace = af.getDefaultAddressSpace()

    labeled = 0
    rewrote = 0

    # Try to rename the anonymous local (best-effort)
    try:
        symmap = high_func.getLocalSymbolMap()
        for s in symmap.getSymbols():
            dt = str(s.getDataType())
            if ("undefined4" in dt) or ("uint32" in dt) or ("ulong" in dt) or ("undefined3" in dt):
                try:
                    nm = s.getName()
                    if nm.startswith("local_") or "unaff" in nm:
                        s.rename("resume_pc")
                        break
                except Exception:
                    pass
    except Exception:
        pass

    #  Patterns that match both 32-bit and 20-bit store to SP-k (k in {3,4})
    #    Examples it accepts:
    #      *(undefined4 *)(SP - 4) = 0x1234;
    #      *(undefined3 *)(SP - 3) = 0x12345;
    #      *(undefined3 *)(fp - 3) = (int3)0x12345;
    #
    _PAT_RESUME = re.compile(
        r"""\*\s*\(\s*(?:undefined4|uint32_t|ulong|long|undefined3|int3)\s*\*\)\s*
             \(\s*[^)]*-\s*(?P<ofs>3|4)\s*\)\s*=\s*
             (?:\(\s*(?:int3|uint32_t|ulong|long)\s*\)\s*)?
             0x(?P<hex>[0-9A-Fa-f]{1,8})\s*;""",
        re.X
    )

    def _fmt_hex20(v):
        # Pretty print: 20-bit => 5 hex digits; 16-bit => 4; else generic
        if v <= 0xFFFF:
            return "0x%04X" % v
        if v <= 0xFFFFF:
            return "0x%05X" % v
        return "0x%X" % v

    def _mk_addr20(raw):
        """Map raw constant to a program address, preferring 20-bit."""

        #
        try:
            a = dspace.getAddress(raw & 0xFFFFF)
            if mem.contains(a):
                return a
        except Exception:
            pass
        
        try:
            a = dspace.getAddress(raw)
            if mem.contains(a):
                return a
        except Exception:
            pass
        return None

    #  Scan leaf tokens for the pattern, rewrite, and label
    for tok in tokens:
        s = str(tok)
        # Fast-filter: must look like a pointer store of a constant
        if "*(" not in s or "= 0x" not in s:
            continue
        m = _PAT_RESUME.search(s)
        if not m:
            continue

        val = int(m.group("hex"), 16)
        ofs = int(m.group("ofs"))  # 3 or 4; we don't currently use it beyond diagnostics

        a = _mk_addr20(val)
        if a is not None:
            try:
                fpa.createLabel(a, "L_resume_%s" % _fmt_hex20(val).replace("0x", ""), True)
                labeled += 1
            except Exception:
                pass

        # Rewrite the assignment at this token site
        line = "resume_pc = %s; // Dirty430: resume point" % _fmt_hex20(val)
        try:
            addr_for_replace = tok.getMinAddress()
        except Exception:
            addr_for_replace = None

        if addr_for_replace and replace_tokens(tokens, addr_for_replace, line):
            rewrote += 1

    if labeled or rewrote:
        _log("decomp: resume points labeled=%d, rewritten=%d" % (labeled, rewrote))


def annotate_store16_msp430x20_runs_all_in_one(high_func, min_run=2, gap_max=8,
                                               require_20bit=False,  # <- default relaxed now
                                               debug=False, debug_dump_limit=60):
    """
    MSP430X store-run annotator (relaxed):
      - Finds STORE ops and tries to group into runs.
      - Primary test: address-chain has AND with all-ones (16–20 bits).
      - Fallback: many STORES whose address varnode is the *same register*
                  within a short p-code distance (Ghidra already truncated).
      - Classifies run as memset? (value==0), memcpy? (value comes from LOAD),
        or table-fill? (value is CONST code-like).
      - Annotates first op in a run + per-op light tags.

    Tuning:
      * increase min_run / change gap_max to be stricter/looser.
      * set require_20bit=True to only keep runs with explicit mask evidence.
    """
    def _prog():
        try: return PROGRAM
        except NameError: return None
    def _curprog():
        try: return currentProgram
        except NameError: return None

    def _append_eol_comment_at(addr, text):
        prog = _prog() or _curprog()
        if not prog or not addr: return False
        try:
            listing = prog.getListing()
            cu = listing.getCodeUnitAt(addr)
            if cu is None:
                try: disassemble(addr)
                except Exception: pass
                cu = listing.getCodeUnitAt(addr)
            if cu is None: return False
            old = cu.getComment(CodeUnit.EOL_COMMENT)
            cu.setComment(CodeUnit.EOL_COMMENT, (old + " | " + text) if old else text)
            try: createBookmark(addr, "Dirty430", text)
            except Exception: pass
            return True
        except Exception:
            return False

    def _vn_size(vn):
        try: return vn.getSize()
        except: return None

    def _is_all_ones_const(vn):
        try:
            if not vn or not vn.isConstant(): return (False, 0)
            val = int(vn.getOffset()) & 0xFFFFFFFF
            if val == 0: return (False, 0)
            if (val & (val + 1)) != 0: return (False, 0)  # not (2^n - 1)
            bits = (val + 1).bit_length() - 1
            return (8 <= bits <= 32, bits if 8 <= bits <= 32 else 0)
        except: return (False, 0)

    def _mask_bits(vn):
        ok, bits = _is_all_ones_const(vn)
        return bits if ok else 0

    def _chain_mask_bits(vn, budget=16):
        """Walk def chain to find an INT_AND with an all-ones constant."""
        cur, steps, best = vn, 0, 0
        while cur and steps < budget:
            try: defop = cur.getDef()
            except: defop = None
            if defop is None: break
            opc = defop.getOpcode()
            if opc == PcodeOp.INT_AND:
                try:
                    n = getattr(defop, "getNumInputs", defop.getInputCount)()
                    for i in range(n):
                        mb = _mask_bits(defop.getInput(i))
                        best = max(best, mb)
                    # continue chasing non-const input
                    a0, a1 = defop.getInput(0), defop.getInput(1)
                    cur = a0 if (a0 and not a0.isConstant()) else (a1 if a1 and not a1.isConstant() else None)
                except: break
            elif opc in (PcodeOp.INT_ADD, PcodeOp.PTRADD, PcodeOp.PTRSUB,
                         PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
                try: cur = defop.getInput(0)
                except: break
            else:
                break
            steps += 1
        return best

    def _classify_value(val_vn, budget=8):
        try:
            if val_vn and val_vn.isConstant():
                v = int(val_vn.getOffset()) & 0xFFFFFFFF
                if v == 0:
                    return "memset?"
                # crude “code-like” heuristic: near the function, high bit clear
                return "table-fill?" if v < 0x200000 else "const"
        except: pass
        cur, steps = val_vn, 0
        while cur and steps < budget:
            try: defop = cur.getDef()
            except: defop = None
            if defop is None: break
            if defop.getOpcode() == PcodeOp.LOAD:
                return "memcpy?"
            if defop.getOpcode() in (PcodeOp.COPY, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
                try: cur = defop.getInput(0)
                except: break
            else:
                break
            steps += 1
        return "store"

    def _addr_key(vn):
        """Key used for fallback grouping: same base varnode identity (register/unique)."""
        try:
            if vn is None: return None
            sp = vn.getSpace()
            sid = sp.getName() if sp else "?"
            off = vn.getOffset()
            sz  = vn.getSize()
            # For registers: (space="register", off=regnum)
            return (sid, int(off), int(sz))
        except: return None

    def _dump_store(addr, op):
        try: nin = op.getNumInputs()
        except: nin = op.getInputCount()
        av = op.getInput(1) if nin >= 2 else None
        vv = op.getInput(2) if nin >= 3 else None
        mb = _chain_mask_bits(av) if av else 0
        try: _log("[store-shape] @%s mask=%db val_size=%s addr_v=%s val_v=%s :: %s" %
                  (addr, mb, _vn_size(vv), av, vv, op))
        except: pass

    # Collect all pcode ops
    ops = []
    for bb in high_func.getBasicBlocks():
        it = bb.getIterator()
        while it.hasNext():
            op = it.next()
            try: addr = op.getSeqnum().getTarget()
            except: addr = None
            ops.append((addr, op))

    if debug:
        dumped = 0
        for addr, op in ops:
            if op.getOpcode() == PcodeOp.STORE:
                _dump_store(addr, op)
                dumped += 1
                if dumped >= debug_dump_limit: break

    # Primary candidates (mask-based) + fallback (same-base register)
    mask_cands = []
    reg_cands  = []  # (idx, addr, kind, basekey)

    for idx, (addr, op) in enumerate(ops):
        if op.getOpcode() != PcodeOp.STORE:
            continue
        try: nin = op.getNumInputs()
        except: nin = op.getInputCount()
        addr_v = op.getInput(1) if nin >= 2 else None
        val_v  = op.getInput(2) if nin >= 3 else None

        kind   = _classify_value(val_v)
        mbits  = _chain_mask_bits(addr_v) if addr_v is not None else 0
        basek  = _addr_key(addr_v)

        if mbits >= 16:
            mask_cands.append((idx, addr, kind, mbits))
        elif basek is not None:
            # fallback track by same base register/unique
            reg_cands.append((idx, addr, kind, basek))

    # Keep only mask_cands if require_20bit; else we can use both sources.
    pools = []
    if mask_cands and require_20bit:
        pools.append(("20b-mask", mask_cands))
    else:
        if mask_cands: pools.append(("20b-mask", mask_cands))
        if reg_cands:  pools.append(("same-base", reg_cands))

    annotated_total = 0

    for label, pool in pools:
        # group runs by proximity (and by same base for the fallback pool)
        runs, cur, prev = [], [], None
        same_base = (label == "same-base")
        cur_base  = None

        for (idx, addr, kind, extra) in pool:
            if not cur:
                cur = [(idx, addr, kind, extra)]
                prev = idx
                cur_base = extra if same_base else None
                continue
            close = (idx - prev) <= gap_max
            same  = (extra == cur_base) if same_base else True
            if close and same:
                cur.append((idx, addr, kind, extra))
            else:
                if len(cur) >= min_run:
                    runs.append(cur)
                cur = [(idx, addr, kind, extra)]
                cur_base = extra if same_base else None
            prev = idx
        if len(cur) >= min_run:
            runs.append(cur)

        if debug:
            _log("[store-%s] runs: %d" % (label, len(runs)))

        # annotate
        for run in runs:
            head = run[0][1]
            kinds = sorted(set(k for (_, _, k, _) in run))
            if label == "20b-mask":
                max_mb = max((mb for (_, _, _, mb) in run), default=0)
                tag = "EA %db" % max_mb if max_mb else "EA ?"
            else:
                tag = "same-base"
            summary = "Dirty430: %s x%d (%s)" % ("/".join(kinds), len(run), tag)
            if _append_eol_comment_at(head, summary):
                annotated_total += 1
            for (_, a, k, _) in run:
                _append_eol_comment_at(a, "Dirty430: %s" % k)

    if debug:
        _log("[store-relaxed] runs annotated: %d" % annotated_total)
    return annotated_total


def _append_eol_comment(addr, text):
    """Append (or set) an EOL comment at addr."""
    prog = PROGRAM or currentProgram
    if prog is None or addr is None:
        return False
    try:
        listing = prog.getListing()
        cu = listing.getCodeUnitAt(addr)
        if cu is None:
            # try to get something to attach to (disassemble if needed)
            try:
                disassemble(addr)
            except Exception:
                pass
            cu = listing.getCodeUnitAt(addr)
        if cu is None:
            _log("[test] No code unit at %s" % fmt_addr(addr), "warn", always=True)
            return False
        old = cu.getComment(CodeUnit.EOL_COMMENT)
        cu.setComment(CodeUnit.EOL_COMMENT, (old + " | " + text) if old else text)
        try:
            createBookmark(addr, "Dirty430", text)
        except Exception:
            pass
        return True
    except Exception as e:
        _log("[test] EOL comment failed at %s: %s" % (fmt_addr(addr), e), "warn", always=True)
        return False

def add_test_comment_on_entry(func, eol_text="Dirty430 TEST: entry EOL OK", plate_text=None):
    """
    Add a test EOL comment at the entry instruction, and an optional plate comment
    on the function. Returns True if EOL set.
    """
    try:
        entry = func.getEntryPoint()
        ok = _append_eol_comment(entry, eol_text)
        if plate_text:
            try:
                func.setComment(plate_text)
            except Exception:
                pass
        if ok:
            _log("[test] Added EOL at entry %s for %s" % (fmt_addr(entry), func.getName()), always=True)
        return ok
    except Exception as e:
        _log("[test] add_test_comment_on_entry failed: %s" % e, "warn", always=True)
        return False

def add_comment_on_first_c_statement(func, text="Dirty430 TEST: first C stmt"):
    """
    Finds the first Clang token group in the decompiled C and drops an EOL comment
    at that address. Useful to prove token->address mapping.
    """
    try:
        ifc = DecompInterface()
        ifc.openProgram(PROGRAM or currentProgram)
        dr = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())
        if not dr or not dr.decompileCompleted():
            _log("[test] decompile failed", "warn", always=True)
            return False
        root = dr.getCCodeMarkup()
        try:
            from ghidra.app.decompiler import ClangTokenGroup
        except Exception:
            try:
                from ghidra.app.decompiler.clang import ClangTokenGroup
            except Exception:
                ClangTokenGroup = None
        if ClangTokenGroup is None or root is None:
            _log("[test] no clang tokens available", "warn", always=True)
            return False

        # walk to find the first child group with an address
        st = [root]
        while st:
            g = st.pop()
            if isinstance(g, ClangTokenGroup):
                try:
                    a = g.getMinAddress()
                except Exception:
                    a = None
                if a is not None:
                    return _append_eol_comment(a, text)
                # depth-first
                for i in range(g.numChildren() - 1, -1, -1):
                    st.append(g.Child(i))
        _log("[test] no token group with address found", "warn", always=True)
        return False
    except Exception as e:
        _log("[test] add_comment_on_first_c_statement failed: %s" % e, "warn", always=True)
        return False





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

    annotate_store16_msp430x20_runs_all_in_one(
        high_func,
        min_run=2,
        gap_max=8,
        require_20bit=False,  
        debug=True,
        debug_dump_limit=80
    )


    memset_replace(high_func, tokens)
    pass_resume_points(high_func, tokens)


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

