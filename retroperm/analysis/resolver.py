import inspect

import angr
import pyvex
from utils import get_arg_locations, string_at_addr, explore


class Resolver:
    """
    Given the address of a call function, resolve the arguments that are passed to it
    """

    def get_calling_convention_analysis(self):
        return self.proj.analyses[angr.analyses.CompleteCallingConventionsAnalysis](recover_variables=True)

    def __init__(self, proj: angr.project.Project, cfg: angr.analyses.forward_analysis.forward_analysis.ForwardAnalysis):
        # print(inspect.getmro(type(cfg))) > <class 'angr.analyses.cfg.cfg_fast.CFGFast'>,
        # <class 'angr.analyses.forward_analysis.forward_analysis.ForwardAnalysis'>, <class 'typing.Generic'>,
        # <class 'angr.analyses.cfg.cfg_base.CFGBase'>, <class 'angr.analyses.analysis.Analysis'>, <class 'object'>
        self.proj = proj
        self.cfg = cfg
        self.ccca = self.get_calling_convention_analysis()
        self._simprocs = proj._sim_procedures
        # print(self._simprocs)

    def resolve_simproc_args(self, simproc: angr.SimProcedure):
        # TODO
        pass

    def resolve_args_of_call(self, call_addr):
        """
        Resolve the arguments that are passed to a function call
        """
        # Get the IR instruction block at the call address
        # TODO: This is not the correct way to get the full block
        # > This only gets the stuff relevant to the single call command
        call_block = self.proj.factory.block(call_addr)
        # Get the target of the call
        target = call_block.capstone.insns[0].op_str
        print(target)
        # Convert to int
        try:
            target = int(target, 16)
        except ValueError:
            # Not a hex string, meaning register
            # TODO: Resolve register
            pass


        # Get the calling convention of the target function
        target_arg_locations = get_arg_locations(self.ccca.kb.functions[target])
        # Convert list of args to list of strings
        target_arg_locations = [arg.reg_name for arg in target_arg_locations]
        # Filter for any PUTS statements that target a register in target_arg_locations
        for stmt in block.vex.statements:
            if isinstance(stmt, pyvex.stmt.Put):
                reg = self.proj.arch.register_names[stmt.offset]
                print(reg)
                print(target_arg_locations)
                if reg in target_arg_locations:
                    print("Found arg:", reg)
                    print(string_at_addr(self.cfg, stmt.data.con.value, self.proj))

        # TODO: Link output of this to dictionary of abusable arguments in a later execution stage

        # print(block.vex.pp())

        # for func in self.cfg.kb.functions.values():
        #     for block in func.blocks:
        #         for instruction in block.capstone.insns:
        #             if instruction.mnemonic == 'call':
        #                 target = instruction.op_str
        #                 # Convert to int
        #                 try:
        #                     target = int(target, 16)
        #                 except ValueError:
        #                     # Not a hex string, meaning register
        #                     # TODO: Resolve register
        #                     pass
        #                 for stmt in block.vex.statements:
        #                     if isinstance(stmt, pyvex.stmt.Put):
        #                         reg = self.proj.arch.register_names[stmt.offset]
        #                         # print(reg)
        #                         if reg in open_arg_locations:
        #                             print("Found arg:", reg)
        #                             print(string_at_addr(cfg, stmt.data.con.value, proj))


if __name__ == '__main__':
    proj1 = angr.Project('../../executables/open_example', auto_load_libs=False)

    cfg1 = proj1.analyses.CFGFast.prep()()

    # Hardcoded values:
    '''
    open_addr: 0x4010d0
    Found call to open at 0x401220
    '''
    open_addr = 0x4010d0
    call_loc = 0x401220

    # Create resolver
    resolver = Resolver(proj1, cfg1)

    # Resolve args
    args = resolver.resolve_args_of_call(call_loc)
    # print(args)
