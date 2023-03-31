from typing import Dict
import angr


class RetropermProject:
    def __init__(self, binary_path):
        self.binary_path = binary_path

    def resolve_abusable_functions(self):
        resolved_data = {}

        # For every abusable function in the binary
        # -> Resolve the values of the arguments that are passed to the function


        # Determine the abusable functions in the binary
        from reference.utils_angrmgmt import string_at_addr
        from retroperm.analysis.utils import explode
        from utils import get_arg_locations, explore
        from data import important_func_args

        import logging

        logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.FATAL)
        logging.getLogger('angr.project').setLevel(logging.FATAL)
        logging.getLogger('cle.loader').setLevel(logging.FATAL)

        proj = angr.Project('../executables/open_example', auto_load_libs=False)
        cfg = proj.analyses.CFGFast.prep()()
        ccca = proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis].prep()(recover_variables=True)
        s = proj.factory.blank_state(addr=0x4005e0)

        call_blocks = set()
        for func in cfg.kb.functions.values():
            for block in func.blocks:
                # handle blocks with no data
                if block.size == 0:
                    continue
                # Vex block
                vex_block: pyvex.block.IRSB = block.vex
                if (vex_block.jumpkind == 'Ijk_Call'):
                    # print(vex_block)
                    # print("Found call at", hex(block.addr))
                    try:
                        # print("Call goes to", vex_block.next.constants[0].value)
                        call_target = vex_block.next.constants[0].value
                    except:
                        # print("Call goes to unknown address")
                        continue

                    call_target_symbol = cfg.kb.functions.function(addr=call_target)

                    if call_target_symbol is not None:
                        # Check if symbol is hooked
                        if not proj.is_symbol_hooked(call_target_symbol.name):
                            continue
                        simproc = proj.symbol_hooked_by(call_target_symbol.name)
                        if simproc:
                            if simproc.__class__ in important_func_args:
                                print("Important function:", simproc.__class__, important_func_args[simproc.__class__])
                                important_arg_nums = important_func_args[simproc.__class__]
                                # Get the calling convention of the target function
                                target_arg_locations = get_arg_locations(ccca.kb.functions[call_target])
                                target_arg_locations = [arg.reg_name for arg in target_arg_locations]
                                important_args = [target_arg_locations[arg_num] for arg_num in important_arg_nums]
                                print("important_args:", important_args)

                                # Get simproc prototype
                                simproc_prototype = simproc.prototype
                                print("simproc_prototype:", simproc_prototype)
                                print("simproc_prototype.args:", simproc_prototype.args)
                                # explore(simproc_prototype.args[1])

                                for stmt in vex_block.statements:
                                    # print("stmt:", stmt)
                                    if isinstance(stmt, pyvex.stmt.Put):
                                        reg = proj.arch.register_names[stmt.offset]
                                        # print(reg)
                                        if reg in important_args:
                                            print(reg)
                                            # Find the argument number
                                            arg_num = important_args.index(reg)
                                            if simproc_prototype.args[
                                                arg_num].__class__ == angr.sim_type.SimTypePointer:
                                                print(string_at_addr(cfg, stmt.data.con.value, proj))
                                            elif simproc_prototype.args[arg_num].__class__ == angr.sim_type.SimTypeInt:
                                                print(hex(stmt.data.con.value))
                                            else:
                                                print("Unknown type:", simproc_prototype.args[arg_num].__class__)

        return resolved_data

class ResolvedFunction:
    def __init__(self, resolved_function_address, args_by_location: Dict[int, Dict[str, str]]):
        self.resolved_function_address = resolved_function_address
        self.args_by_location = args_by_location
