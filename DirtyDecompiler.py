# DirtyDecompiler.py

# Performs multiple cleanups on MSP430 decompiled output:
# NOTE: Alot of this was adapted from an old IDA Script I had written.
#       Still debugging heavy before I merge into Dirty430.py. One Ghidra
#       Module  will be much simpler to get on machines probably...

#  - Arithmetic simplification (mul/div). No mul/div unit.
#  - Bitmask macro cleanup
#  - Switch recovery
#  - Struct detection
#  - Peripheral register renaming (if mapping provided)
#  - Constant folding
#  - Adjusting any weird stack behavior


#@author J. DeFrancesco
#@category MSP430 Decompiler Cleanup

from ghidra.util import Msg # pyright: ignore[reportMissingModuleSource]
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.clang import ClangTokenGroup
from ghidra.program.model.listing import CodeUnit



## UTIL FUNCS TEMP.

VERBOSE = True

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
        _log(msg)
    except Exception:
        pass


def get_decompiled_function(func):
    """This call initializes new decompiler process. Only needs to be called when first ran
    
    
    NOTE: currentProgram is set by Ghidra along with the others in their scripting docs..
    """

    ifc = DecompInterface()
    ifc.openProgram(currentProgram)

    return ifc.decompileFunction(func, 60, ConsoleTaskMonitor())


def replace_tokens(tokens, start_addr, new_text):
    """Replaces tokens is our utility function used to replace C operators and 

    similar tokens. 
    """
    
    for tok in tokens:
        if tok.getMinAddress() == start_addr:
            parent = tok.getParent()
            if isinstance(parent, ClangTokenGroup):
                parent.removeChildren()
                parent.addText(new_text)
                return True
                
    return False


def simplify_arithmetic(high_func, tokens):
    """Replace repeated-addition loops with multiply op."""

    for block in high_func.getBasicBlocks():
        ops = list(block.getPcodeOps())

        # Look for basic blocks that use repeated addition/sub heuristic.
        add_ops = [op for op in ops if op.getOpcode() == PcodeOp.INT_ADD]
        sub_ops = [op for op in ops if op.getOpcode() == PcodeOp.INT_SUB]

        if len(add_ops) == 1 and len(sub_ops) == 1:
            addr = block.getStart()
            # Provide more readable C op. subs..
            if replace_tokens(tokens, addr, "sum = counter * constant; // simplified"):
                _log("[Arithmetic] Simplified loop at %s " % fmt_addr(addr))

    return


def bitmask_macros(high_func, tokens):
    """Convert reg |= / &= constants into macros for clarity.. 
    
    A lot of bit mask ops take place for things like bit banging over GPIO lines
    or masking parts of address.
    """

    # Simple and might not catch everything but we will try
    for block in high_func.getBasicBlocks():
        ops = list(block.getPcodeOps())
        for op in ops:
            if op.getOpcode() in (PcodeOp.INT_AND, PcodeOp.INT_OR):

                out = op.getOutput()
                inputs = [op.getInput(i) for i in range(op.getNumInputs())]

                if len(inputs) == 2 and inputs[1].isConstant():
                    const_val = inputs[1].getOffset()

                    if op.getOpcode() == PcodeOp.INT_OR:
                        # macro = f"SET_BITS({out.getHigh().getName()}, 0x{const_val:X})"
                        # Keep forgetting no f strings yet...
                        macro = "SET_BITS({}".format(out.getHigh().getName()) + " ,0x{:X}".format(const_val)
                    else:
                        macro = "CLEAR_BITS({}".format(out.getHigh().getName()) + " ,0x{:X}".format(const_val)
                    
                    replace_tokens(tokens, op.getSeqnum().getTarget(), macro)
                    _log("[Bitmask] Rewrote at %s "  % op.getSeqnum().getTarget())

    return

def constant_folding(high_func, tokens):
    """Replace sequences like x = 0; x += y; with x = y;
    
    
    You'd think they do this already but no?? It doesn't seem to work all time
    time for some reason but that might be a configuration thing.
    """

    for block in high_func.getBasicBlocks():
        ops = list(block.getPcodeOps())
        if len(ops) >= 2:
            # Get first and second operators
            first, second = ops[0], ops[1]

            if (first.getOpcode() == PcodeOp.COPY and first.getInput(0).isConstant() and
                second.getOpcode() == PcodeOp.INT_ADD and second.getInput(0) == first.getOutput()):

                addr = first.getSeqnum().getTarget()

                if replace_tokens(tokens, addr, "x = y; // const-folded"):
                    _log("[ConstFold] Folded at %s" %  fmt_addr(addr))

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
        # Look for these tokens with cast and setting to zero.
        if "*(" in s and "= 0" in s:
            parent = tok.getParent()
            if parent:
                try:
                    parent.addComment("dirty430: memset(buffer, 0, len) candidate")
                    hints += 1
                except: pass
    if hints: 
        _log("dirty430: memset hints %d" %  hints)

    return


def struct_recovery(high_func, tokens):
    """Group sequential memory addresses with different offsets signals possible struct.
    
    Consistent offsets normally mean arrays. These are super rough heuristics but generally
    work well enough.
    """

    addr_list = []
    for block in high_func.getBasicBlocks():
        for op in block.getPcodeOps():
            
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
            
    return 
            
def switch_table_hint(high_func, tokens):
    """
    switch_table_hint suggests the replacement of a switch with a cleaner
    table lookup in certain cases.

    Table lookups occur a lot with various functions including crypto functions
    which might make idenitfy them a bit more clear.
    """

    collapsed = 0
    for bb in high_func.getBasicBlocks():
        ops = list(bb.getPcodeOps())
        consts = []
        target = None

        for op in ops:
            if op.getOpcode() == PcodeOp.COPY and op.getInputCount() == 1 and op.getInput(0).isConstant():
                consts.append(op.getInput(0).getOffset())

                if op.getOutput(): 
                    target = op.getOutput().getHigh().getName()

        if target and len(consts)>=3:
            # construct table C looking thingy for now.
            # These are constants of a possible table in hex.
            arr_elements = ", ".join(f"0x{v:X}" for v in consts)
            # C table replacement. Just using this for time being can fill in real types might be used 
            # when i've proved it worth it.
            text = "static const uint16_t dirty430_tbl[] = \{ {} \};\n".format(arr_elements) +  "{} = dirty430_tbl[...]; ".format(target)
            if  replace_tokens(tokens, bb.getStart(), text):
                collapsed += 1

    if collapsed: 
        _log("[dirty430] switch lookup has been collapsed: %s" % collapsed)

    return


def main():
    """Main. NOTE: THIS IS MEANT TO BE RUN PER FGUNCTION..
    
    
    For now I am keeping this seperate from phase one clean up for debug utility and ease.
    Will combine into a single Dirty430 script for portability with minimal dependencies!
    """


    func = getFunctionContaining(currentAddress)
    if not func:
        _log("dirty430: No function at current address.")
        return

    res = get_decompiled_function(func)
    if not res.decompileCompleted():
        _log("dirty430: Decompilation failed for %s"  func.getName())
        return

    high_func = res.getHighFunction()
    tokens = res.getCFunction().getTokens()

    simplify_arithmetic(high_func, tokens)
    bitmask_macros(high_func, tokens)
    constant_folding(high_func, tokens)
    switch_table_hint(high_func, tokens)
    struct_recovery(high_func, tokens)
    memset_replace(high_func, tokens)


    # peripheral_renaming(high_func, tokens) - done by first script as pre-pass for now. But just in case
    # this might need a second pass or something..


if __name__ == "__main__":
    main()

