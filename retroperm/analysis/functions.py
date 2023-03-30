import inspect
from typing import List

import angr
from . import resolver
from pprint import pprint

from reference.utils import explore

abusable_function_args = {
    # open: [0: char* pathname, 1: int flags, 2: mode_t mode]
    angr.SIM_PROCEDURES['posix']['open']().__class__: [0, 1],
    # fopen: [0: char* filename, 1: char* mode]
    angr.SIM_PROCEDURES['libc']['fopen']().__class__: [0, 1],

}


def get_abusable_function_args(simproc: angr.SimProcedure):
    """
    Takes input simproc and returns a list of int arguments that can be abused
    """
    if simproc.__class__ in abusable_function_args:
        return abusable_function_args[simproc.__class__]
    else:
        return []


def get_function_arg_locs(func: angr.knowledge_plugins.functions.function.Function) -> \
        List[angr.calling_conventions.SimRegArg]:
    """
    Takes input kb.function and returns the argument locations
    """
    return func.arguments


if __name__ == '__main__':
    proj = angr.Project('../../executables/open_example', auto_load_libs=False)

    cfg = proj.analyses.CFGFast()

    func = cfg.functions['open']

    print(get_function_arg_locs(func))

    func_addr = func.addr

    print(func_addr)

    print(proj._sim_procedures)

    # simproc = proj._sim_procedures[func_addr]

    for simproc in proj._sim_procedures.values():
        print(simproc)
        # print(pprint(vars(angr.SIM_PROCEDURES['posix']['open']())),
              # pprint(vars(simproc)))
        # print(inspect.getmro(simproc.__class__))
        # print(inspect.getmro(angr.SIM_PROCEDURES['posix']['open']().__class__))

        print(get_abusable_function_args(simproc))
        print()
