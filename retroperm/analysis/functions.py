import inspect

import angr
import resolver
from pprint import pprint

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
    if simproc in abusable_function_args:
        return abusable_function_args[simproc]
    else:
        return []


def get_function_arg_locs(simproc: angr.SimProcedure):
    """
    Takes input simproc and returns the calling convention
    """
    return simproc.cc


if __name__ == '__main__':
    proj = angr.Project('../../executables/open_example', auto_load_libs=False)

    for simproc in proj._sim_procedures.values():
        print(simproc)
        # print(pprint(vars(angr.SIM_PROCEDURES['posix']['open']())),
              # pprint(vars(simproc)))
        # print(inspect.getmro(simproc.__class__))
        # print(inspect.getmro(angr.SIM_PROCEDURES['posix']['open']().__class__))

        print(get_function_arg_locs(simproc))
        print(get_abusable_function_args(simproc.__class__))
        print()
