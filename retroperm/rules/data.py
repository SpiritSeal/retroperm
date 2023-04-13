import angr

important_func_args = {
    # Filesystem Rules
    # - Note: Open mode is like append async, etc whereas fopen mode is like open's mode + flags
    # open: [0: char* pathname, 1: int flags, 2: mode_t mode]
    angr.SIM_PROCEDURES['posix']['open']().__class__: {0: 'filename', 1: 'flags'},
    # fopen: [0: char* filename, 1: char* mode]
    angr.SIM_PROCEDURES['libc']['fopen']().__class__: {0: 'filename', 1: 'mode'},

    # Network Rules
    # socket: [0: int domain, 1: int type, 2: int protocol]
    angr.SIM_PROCEDURES['posix']['socket']().__class__: {0: 'domain', 1: 'type', 2: 'protocol'},

}

