import angr
import pyvex

from reference.utils_angrmgmt import string_at_addr
from retroperm.analysis.utils import explode
from utils import get_arg_locations
from data import important_func_args

proj = angr.Project('../executables/open_example', auto_load_libs=False)
cfg = proj.analyses.CFGFast.prep()()
ccca = proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

for func in cfg.kb.functions.values():
    for block in func.blocks:
        for instruction in block.capstone.insns:
            if instruction.mnemonic == 'call':
                call_target = instruction.op_str
                # Found call
                print("Found call to", call_target, "at", hex(block.addr))

                # Convert to int
                try:
                    call_target = int(call_target, 16)
                except ValueError:
                    # Not a hex string, meaning register
                    # TODO: Resolve register
                    continue
                # Get the symbol of the call target
                call_target_symbol = cfg.kb.functions.function(addr=call_target)

                if call_target_symbol is not None:
                    print("Working on", call_target_symbol.name)
                    # Get Simproc from symbol
                    simproc = proj.symbol_hooked_by(call_target_symbol.name)
                    if simproc:
                        print("Simproc:", simproc)
                        if simproc.__class__ in important_func_args:
                            print("Important function:", simproc.__class__, important_func_args[simproc.__class__])
                            important_arg_nums = important_func_args[simproc.__class__]

                            # Get the calling convention of the target function
                            target_arg_locations = get_arg_locations(ccca.kb.functions[call_target])
                            target_arg_locations = [arg.reg_name for arg in target_arg_locations]
                            print("target_arg_locations:", target_arg_locations)
                            important_args = [target_arg_locations[arg_num] for arg_num in important_arg_nums]
                            print("important_args:", important_args)

                            # for reg in important_args:
                            #     print("Found arg:", reg)
                            #     print(string_at_addr(cfg, stmt.data.con.value, proj))
                print()
