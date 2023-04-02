# Arg locations of functions in binary
from typing import List
import angr
from angr.analyses import CompleteCallingConventionsAnalysis
from angr.sim_type import SimTypeFunction
# from data import abusable_funcs
from .utils_angrmgmt import string_at_addr
import pprint as pprint


def get_arg_locations(func: angr.knowledge_plugins.functions.function.Function) -> \
        List[angr.calling_conventions.SimRegArg]:
    """
    Get the argument locations of a function
    """
    # TODO: Assert Calling Convention exists

    return func.arguments

# def is_abusable(func: angr.sim_procedure.SimProcedure) -> bool:
#     """
#     Check if a simproc function is in the abusable list
#     """
#     if func in abusable_funcs:
#         return True


def get_abusable_arg_locations(func: angr.knowledge_plugins.functions.function.Function) -> \
        List[angr.calling_conventions.SimRegArg]:
    """
    Get the argument locations of a function that are potentially abusable
    """


def explore(obj: any):
    """
    Explore an object
    """
    print(type(obj))
    print(obj)
    print(dir(obj))

def explode(obj: any):
    """
    Explode the properties of an object
    """
    pprint(vars(obj))


if __name__ == "__main__":
    proj = angr.Project('../executables/open_example', auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    open_func = cfg.functions['open']
    open_addr = open_func.addr

    ccca = proj.analyses[CompleteCallingConventionsAnalysis].prep()(recover_variables=True)

    # ccca = proj.analyses.CompleteCallingConventionsAnalysis(recover_variables=True)

    for i in ccca.kb.functions:
        # print(i)
        # print(ccca.kb.functions[i].calling_convention)
        print(ccca.kb.functions[i].name)
        # if ccca.kb.functions[i].arguments:
        #     print(type(ccca.kb.functions[i].arguments[0]))
        # print(type(ccca.kb.functions[i]))
        print(get_arg_locations(ccca.kb.functions[i]))
        print()
