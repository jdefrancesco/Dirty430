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


#@author J. DeFrancesco
#@category MSP430 Decompiler Cleanup


from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler.clang import ClangTokenGroup
from ghidra.program.model.listing import CodeUnit


def get_decompiled_function(func):
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    return ifc.decompileFunction(func, 60, ConsoleTaskMonitor())


def replace_tokens(tokens, start_addr, new_text):
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
        add_ops = [op for op in ops if op.getOpcode() == PcodeOp.INT_ADD]
        sub_ops = [op for op in ops if op.getOpcode() == PcodeOp.INT_SUB]
        if len(add_ops) == 1 and len(sub_ops) == 1:
            addr = block.getStart()
            if replace_tokens(tokens, addr, "sum = counter * constant; // simplified"):
                print(f"[Arithmetic] Simplified loop at {addr}")


def bitmask_macros(high_func, tokens):
    """Convert reg |= / &= constants into macros"""

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
                        macro = f"SET_BITS({out.getHigh().getName()}, 0x{const_val:X})"
                    else:
                        macro = f"CLEAR_BITS({out.getHigh().getName()}, 0x{const_val:X})"
                    replace_tokens(tokens, op.getSeqnum().getTarget(), macro)
                    print(f"[Bitmask] Rewrote at {op.getSeqnum().getTarget()}")


def constant_folding(high_func, tokens):
    """Replace sequences like x = 0; x += y; with x = y;

    You'd think they do this already but no??
    """

    for block in high_func.getBasicBlocks():
        ops = list(block.getPcodeOps())
        if len(ops) >= 2:
            first, second = ops[0], ops[1]
            if (first.getOpcode() == PcodeOp.COPY and first.getInput(0).isConstant() and
                second.getOpcode() == PcodeOp.INT_ADD and second.getInput(0) == first.getOutput()):
                addr = first.getSeqnum().getTarget()
                if replace_tokens(tokens, addr, "x = y; // const-folded"):
                    print(f"[ConstFold] Folded at {addr}")



def struct_recovery(high_func, tokens):
    """Group sequential memory addresses -> struct hint"""

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
            replace_tokens(tokens, addr_list[i-1], "// struct field sequence detected")
            print(f"[Struct] Fields near {addr_list[i-1]}")


def main():
    """Main"""

    func = getFunctionContaining(currentAddress)
    if not func:
        print("No function at current address.")
        return

    res = get_decompiled_function(func)
    if not res.decompileCompleted():
        print(f"Decompilation failed for {func.getName()}")
        return

    high_func = res.getHighFunction()
    tokens = res.getCFunction().getTokens()

    simplify_arithmetic(high_func, tokens)
    bitmask_macros(high_func, tokens)
    constant_folding(high_func, tokens)
    switch_recovery(high_func, tokens)
    struct_recovery(high_func, tokens)
    peripheral_renaming(high_func, tokens)


main()

