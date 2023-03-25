import angr
import pyvex

from utils import get_arg_locations, string_at_addr

proj = angr.Project('../executables/open_example', auto_load_libs=False)

cfg = proj.analyses.CFGFast.prep()()

# Get the address of the open function
open_func = cfg.functions['open']
open_addr = open_func.addr

print("open_addr:", hex(open_addr))

# List all of the calls in the binary that point to the open function
open_call_blocks = []

for func in cfg.kb.functions.values():
    for block in func.blocks:
        for instruction in block.capstone.insns:
            if instruction.mnemonic == 'call':
                target = instruction.op_str
                # Convert to int
                try:
                    target = int(target, 16)
                except ValueError:
                    # Not a hex string, meaning register
                    # TODO: Resolve register
                    pass
                if target == open_addr:
                    print("Found call to open at", hex(instruction.address))
                    open_call_blocks.append(block)


# Get calling convention
ccca = proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis](recover_variables=True)
# Get the calling convention of the open function
open_arg_locations = get_arg_locations(ccca.kb.functions[open_addr])
print("open_args:", open_arg_locations)
# print(open_arg_locations[0].reg_name)
# Convert list of args to list of strings
open_arg_locations = [arg.reg_name for arg in open_arg_locations]


# Get the IR of the blocks that call the open function
for block in open_call_blocks:
    # print("Block at", hex(block.addr))
    # print(block.capstone.insns)
    # Filter for any PUTS statements that target a register in open_arg_locations
    for stmt in block.vex.statements:
        # print("stmt:", stmt)
        if isinstance(stmt, pyvex.stmt.Put):
            reg = proj.arch.register_names[stmt.offset]
            # print(reg)
            if reg in open_arg_locations:
                print("Found arg:", reg)
                print(string_at_addr(cfg, stmt.data.con.value, proj))
    # print((block.vex.statements))
    # print(block.vex)
    # print("--------------------")

