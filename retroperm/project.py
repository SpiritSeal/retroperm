from typing import Dict, List
import angr
from reference.utils_angrmgmt import string_at_addr
from .analysis.utils import get_arg_locations
from .rules.data import important_func_args
from .rules import Rule, default_rules
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
        self.resolved_data: Dict[angr.SimProcedure, ResolvedFunctionObject] = {}
        self.rules = set()
        self.resolved_function_data = None

    def get_printable_value(self, reg_arg_type: angr.sim_type.SimTypeReg, value: int) -> str or int:
        if reg_arg_type.__class__ == angr.sim_type.SimTypePointer:
            str_val = string_at_addr(self.cfg, value, self.proj)
            # Strip double quotes
            return str_val[1:-1]
        else:
            return value

    def is_abusable_function(self, func: angr.knowledge_plugins.functions.function.Function):
        """
        :param func: Checks if the function makes a call to a function in the abusable functions list
        :return: Block of the call
        """
        proj = self.proj
        cfg = self.cfg
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
            # If you are still here: congratulations, you matter apparently
            return True
            # return block
        return False

    def get_abusable_functions(self):
        cfg = self.cfg

        important_func_list = []
        for func in cfg.kb.functions.values():
            print(func)
            if not self.is_abusable_function(func):
                continue
            important_func_list.append(func)
        return important_func_list

    def resolve_function_call_block(self, func: angr.knowledge_plugins.functions.function.Function):

        proj = self.proj
        cfg = self.cfg
        ccca = self.ccca

        running_resolved_functions: Dict[angr.sim_procedure.SimProcedure: Dict[int, Dict[str, str | int]]] = {}

        for block in func.blocks:
            resolved_data: Dict[angr.SimProcedure, ResolvedFunctionObject] = {}

            vex_block: pyvex.block.IRSB = block.vex
            cur_addr = vex_block.addr
            call_target = vex_block.next.constants[0].value
            call_target_symbol = cfg.kb.functions.function(addr=call_target)
            # print(block.pp())
            # print(call_target_symbol)
            if not call_target_symbol:
                continue
            simproc = proj.symbol_hooked_by(call_target_symbol.name)

            if simproc.__class__ not in important_func_args:
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

    # for key, value in running_resolved_functions.items():
    #     key: angr.sim_procedure.SimProcedure
    #     resolved_data[key.display_name] = ResolvedFunctionObject(key, value)
    # return resolved_data
    #     ...

    def raf(self):

        proj = self.proj
        cfg = self.cfg
        ccca = self.ccca

        af = self.get_abusable_functions()

        print(proj._sim_procedures.values())
        running_resolved_functions: Dict[angr.sim_procedure.SimProcedure: Dict[int, Dict[str, str | int]]] = {}

        for func in af:
            # # call_target = vex_block.next.constants[0].value
            # call_target_symbol = cfg.kb.functions.function(addr=call_target)
            # simproc = proj.symbol_hooked_by(call_target_symbol.name)
            self.resolve_function_call_block(func)

    def resolve_abusable_functions(self):

        resolved_data: Dict[angr.SimProcedure, ResolvedFunctionObject] = {}

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
                print(important_arg_nums)

                target_arg_locations = [arg.reg_name for arg in get_arg_locations(ccca.kb.functions[call_target])]
                important_args = [target_arg_locations[arg_num] for arg_num in important_arg_nums]

                print(f'{important_arg_nums=}')

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

        for key, value in running_resolved_functions.items():
            key: angr.sim_procedure.SimProcedure
            resolved_data[key.display_name] = ResolvedFunctionObject(key, value)
        return resolved_data

    # Rule Stuff
    def init_rules(self, rule_list: List[Rule], override_default=False):
        # Add the rules to the self.rules
        self.rules = set(rule_list if override_default else (rule_list and default_rules))

    def load_rules(self, rule_list: List[Rule]):
        # Add the rules to the self.rules
        self.rules |= rule_list


    # def validate_rule(self, rule: Rule):


    def validate_rules(self, rule_list=None):
        if rule_list:
            raise NotImplemented
        output = {}
        for rule in self.rules:
            output[rule] = rule

        return output


class ResolvedFunctionObject:
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
