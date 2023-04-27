from typing import Dict, List, Set
import angr
from .analysis.utils import get_arg_locations
from .analysis.utils_angrmgmt import string_at_addr
from .rules.argument_rule import ArgumentRule
from .rules.ban_category_rule import BanCategoryRule
from .rules.ban_library_function_rule import BanLibraryFunctionRule
from .rules.data import important_func_args
from .rules import Rule, default_rules
import pyvex
from sortedcollections import OrderedSet

import logging

logging.getLogger('angr.analyses.reaching_definitions').setLevel(logging.FATAL)
logging.getLogger('angr.project').setLevel(logging.FATAL)
logging.getLogger('cle.loader').setLevel(logging.FATAL)


class RetropermProject:

    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.proj = angr.Project(binary_path, auto_load_libs=False)
        self.cfg = self.proj.analyses.CFGFast.prep()()
        try:
            self.ccca = self.proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis].prep()()
        except:
            self.ccca = None
        self.rules = OrderedSet()
        self.resolved_function_data: Dict[angr.SimProcedure, ResolvedFunctionObject] = {}
        self.resolved_function_data = None
        self.called_symbols: Set[str] | None = None
        self.resolved_project_data: Dict[str, object] = {}
        # self.resolved_project_data: ResolvedProjectData = None

    def get_printable_value(self, reg_arg_type: angr.sim_type.SimTypeReg, value: int) -> str or int:
        if reg_arg_type.__class__ == angr.sim_type.SimTypePointer:
            str_val = string_at_addr(self.cfg, value, self.proj)
            # Strip double quotes
            return str_val[1:-1]
        else:
            return value

    def create_called_symbols_list(self) -> Set[str]:
        proj = self.proj
        cfg = self.cfg

        called_symbols = OrderedSet()
        # for symbol in proj.loader.main_object.symbols:
        #     if proj.is_symbol_hooked(symbol.name):
        #         called_symbols.append(symbol.name)
        for func in cfg.kb.functions.values():
            for block in func.blocks:
                if block.size == 0:
                    continue
                vex_block: pyvex.block.IRSB = block.vex
                cur_addr = vex_block.addr
                if vex_block.jumpkind != 'Ijk_Call' or len(vex_block.next.constants) == 0:
                    continue
                call_target = vex_block.next.constants[0].value
                called_symbols.add(cfg.kb.functions.function(addr=call_target))
        self.called_symbols = called_symbols
        return called_symbols

    def resolve_defined_simproc_args(self):
        proj = self.proj
        cfg = self.cfg
        ccca = self.ccca

        resolved_function_data: Dict[angr.SimProcedure, ResolvedFunctionObject] = {}
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
                # TODO: Transport this to below
                call_target_symbol = cfg.kb.functions.function(addr=call_target)
                if call_target_symbol is None or not proj.is_symbol_hooked(call_target_symbol.name):
                    continue
                simproc = proj.symbol_hooked_by(call_target_symbol.name)
                # TODO: Remove after doing something about the way the things are stored in the lookup table
                # TODO: / create new extended "pass" Simprocs to catch the new targets (see logbook 04-13-23)
                # print(call_target_symbol.name, simproc)
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
                        if not hasattr(stmt.data, "con"):
                            continue
                        # try:
                        ora[arg_num] = self.get_printable_value(simproc.prototype.args[arg_num], stmt.data.con.value)
                        # except:
                        #     print('FAILED ON', stmt)
                        #     exit(1)

                final_resolved_block = {}
                for count, value in enumerate(ora):
                    final_resolved_block[important_arg_nums[count]] = value

                if simproc not in running_resolved_functions:
                    running_resolved_functions[simproc] = {}
                running_resolved_functions[simproc][cur_addr] = final_resolved_block

        for key, value in running_resolved_functions.items():
            key: angr.sim_procedure.SimProcedure
            resolved_function_data[key.display_name] = ResolvedFunctionObject(key, value)
        self.resolved_function_data = resolved_function_data
        return resolved_function_data

    def resolve_abusable_functions(self):

        self.resolved_project_data['resolved_function_data'] = self.resolve_defined_simproc_args()
        self.resolved_project_data['active_symbols'] = self.create_called_symbols_list()
        return self.resolved_project_data

    # Rule Stuff
    def init_rules(self, rule_list: List[Rule], override_default=False):
        # Add the rules to the self.rules
        self.rules = OrderedSet(rule_list if override_default else (rule_list and default_rules))

    def load_rules(self, rule_list: List[Rule]):
        # Add the rules to the self.rules
        self.rules |= rule_list

    def validate_rule(self, rule: Rule) -> str:

        if isinstance(rule, ArgumentRule):
            output: Dict[str, bool] = rule.validate(self.resolved_project_data)
            fails = []
            for key, value in output.items():
                if not value:
                    fails.append(key)
            if fails:
                return f'Failed on {fails}'
            else:
                return 'Passed'
        elif isinstance(rule, BanLibraryFunctionRule):
            return 'Passed' if rule.validate(self.resolved_project_data) else 'Failed'
        elif isinstance(rule, BanCategoryRule):
            return f'Failed on {rule.validate(self.resolved_project_data)}' if rule.validate(self.resolved_project_data) else 'Passed'
        elif isinstance(rule, Rule):
            raise NotImplementedError
        else:
            raise ValueError('Rule not recognized')

    def validate_rules(self, rule_list=None):
        if not rule_list:
            if not self.rules:
                raise ValueError('No rules to validate')
            rule_list = self.rules
        output = {}
        for rule in rule_list:
            output[rule] = self.validate_rule(rule)

        return output


class ResolvedFunctionObject:

    def generate_argument_categories(self):
        argument_types = OrderedSet()
        for key, value in self.args_by_location.items():
            for arg_type, arg_value in value.items():
                argument_types.add(arg_type)
            return argument_types

    def __init__(self, resolved_function_simproc: angr.sim_procedure.SimProcedure,
                 args_by_location: Dict[int, Dict[str, str]]):
        self.resolved_function_simproc = resolved_function_simproc
        self.args_by_location = args_by_location
        # print(self.args_by_location)
        self.argument_types = self.generate_argument_categories()

    def __repr__(self):
        # Example: {'open': <ResolvedFunction: open@[0xdeadbeef, 0xcafebabe, ...]>}
        list_of_addresses = [hex(addr) for addr in list(self.args_by_location.keys())]
        return f"<ResolvedFunction: {self.resolved_function_simproc}@{list_of_addresses}>"


# TODO: Implement this in order to make the code more readable and easier to work with
# class ResolvedProjectData:
#     def __init__(self, rfo: ResolvedFunctionObject = None, called_symbols: List[str] = None):
#         self.resolved_function_data: Dict[angr.SimProcedure, ResolvedFunctionObject] = {}
#         self.active_symbols: List[str] = []










