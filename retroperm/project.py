import re
from pprint import pprint
from typing import Dict, List
import angr
from reference.utils_angrmgmt import string_at_addr
from .analysis.utils import get_arg_locations, explore
from .rules.data import important_func_args
import pyvex

import logging

logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.FATAL)
logging.getLogger('angr.project').setLevel(logging.FATAL)
logging.getLogger('cle.loader').setLevel(logging.FATAL)


class RetropermProject:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.proj = angr.Project(binary_path, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGFast.prep()()
        self.ccca = self.proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis].prep()()
        self.resolved_data: Dict[angr.SimProcedure, ResolvedFunctionData] = {}

    def get_printable_value(self, reg_arg_type: angr.sim_type.SimTypeReg, value: int) -> str or int:
        if reg_arg_type.__class__ == angr.sim_type.SimTypePointer:
            str_val = string_at_addr(self.cfg, value, self.proj)
            # Strip double quotes
            return str_val[1:-1]
        else:
            return value

    def absolute_name(self, simproc: angr.sim_procedure):
        print("Simproc", simproc)
        print("Classname", simproc.__class__)
        print("BEFORE", simproc.__class__.__name__)
        print("ABSOLUTE KEY", re.sub('^angr.simproc', '', simproc.__class__.__name__))
        return re.sub('^angr.simproc', '', simproc.__class__.__name__)

    def resolve_abusable_functions(self):

        resolved_data: Dict[angr.SimProcedure, ResolvedFunctionData] = {}

        proj = self.proj
        cfg = self.cfg
        ccca = self.ccca

        running_resolved_functions: Dict[angr.sim_procedure.SimProcedure: Dict[int, Dict[str, str | int]]] = {}

        for func in cfg.kb.functions.values():
            for block in func.blocks:
                if block.size == 0:
                    continue
                vex_block: pyvex.block.IRSB = block.vex
                cur_addr = vex_block.addr
                if vex_block.jumpkind != 'Ijk_Call' or len(vex_block.next.constants) == 0:
                    continue
                call_target = vex_block.next.constants[0].value
                call_target_symbol = cfg.kb.functions.function(addr=call_target)
                if call_target_symbol is None or not proj.is_symbol_hooked(call_target_symbol.name):
                    continue
                simproc = proj.symbol_hooked_by(call_target_symbol.name)
                if not simproc or simproc.__class__ not in important_func_args:
                    continue

                important_arg_nums = important_func_args[simproc.__class__]

                target_arg_locations = [arg.reg_name for arg in get_arg_locations(ccca.kb.functions[call_target])]
                important_args = [target_arg_locations[arg_num] for arg_num in important_arg_nums]

                # ora stands for ordered_resolved_arguments
                ora: List[int | str | None] = [None] * len(important_args)
                for stmt in vex_block.statements:
                    if not isinstance(stmt, pyvex.stmt.Put):
                        continue
                    stmt: pyvex.stmt.Put
                    reg = proj.arch.register_names[stmt.offset]
                    if reg in important_args:
                        arg_num = important_args.index(reg)
                        ora[arg_num] = self.get_printable_value(simproc.prototype.args[arg_num], stmt.data.con.value)

                final_resolved_block = {}
                for count, value in enumerate(ora):
                    final_resolved_block[important_arg_nums[count]] = value

                if simproc not in running_resolved_functions:
                    running_resolved_functions[simproc] = {}
                running_resolved_functions[simproc][cur_addr] = final_resolved_block

                pprint(vars(simproc))

        for key, value in running_resolved_functions.items():
            key: angr.sim_procedure.SimProcedure
            # resolved_data[self.absolute_name(key)] = ResolvedFunctionData(key, value)
            resolved_data[key.display_name] = ResolvedFunctionData(key, value)
        return resolved_data


class ResolvedFunctionData:
    def __init__(self, resolved_function_simproc: angr.sim_procedure.SimProcedure,
                 args_by_location: Dict[int, Dict[str, str]]):
        # In args_by_location, the first key is the address of the call to the function
        # The key of the nested dict is the function of the argument
        # For example, if the function is open, the first nested dict key would be 'filename'
        # The value of the nested dict is the value of the argument
        self.resolved_function_simproc = resolved_function_simproc
        self.args_by_location = args_by_location

    def __repr__(self):
        # Example: {'open': <ResolvedFunction: open@[0xdeadbeef, 0xcafebabe, ...]>}
        list_of_addresses = [hex(addr) for addr in list(self.args_by_location.keys())]
        return f"<ResolvedFunction: {self.resolved_function_simproc}@{list_of_addresses}>"
