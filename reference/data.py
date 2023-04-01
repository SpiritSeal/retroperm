import angr

important_func_args = {
    # open: [0: char* pathname, 1: int flags, 2: mode_t mode]
    angr.SIM_PROCEDURES['posix']['open']().__class__: [0, 1],
    # fopen: [0: char* filename, 1: char* mode]
    angr.SIM_PROCEDURES['libc']['fopen']().__class__: [0, 1],
}