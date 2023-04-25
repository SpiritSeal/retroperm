import angr
from .ban_library_function_rule import BanLibraryFunctionRule

important_func_args = {
    # Filesystem Rules
    # - Note: Open mode is like append async, etc whereas fopen mode is like open's mode + flags
    # open: [0: char* pathname, 1: int flags, 2: mode_t mode]
    angr.SIM_PROCEDURES['posix']['open']().__class__: {0: 'filename', 1: 'flags'},
    # 'posix_open': {0: 'filename', 1: 'flags'},
    # fopen: [0: char* filename, 1: char* mode]
    angr.SIM_PROCEDURES['libc']['fopen']().__class__: {0: 'filename', 1: 'mode'},

    # Network Rules
    # socket: [0: int domain, 1: int type, 2: int protocol]
    angr.SIM_PROCEDURES['posix']['socket']().__class__: {0: 'domain', 1: 'type', 2: 'protocol'},
    # inet_pton: [0: int af, 1: const char *src, 2: void *dst]
    # angr.SIM_PROCEDURES['libc']['inet_pton']().__class__: {0: 'af', 1: 'src', 2: 'dst'},

    # # connect: [0: int sockfd, 1: const struct sockaddr *addr, 2: socklen_t addrlen]
    # angr.SIM_PROCEDURES['posix']['connect']().__class__: {0: 'sockfd', 1: 'addr', 2: 'addrlen'},
    # # bind: [0: int sockfd, 1: const struct sockaddr *addr, 2: socklen_t addrlen]
    # angr.SIM_PROCEDURES['posix']['bind']().__class__: {0: 'sockfd', 1: 'addr', 2: 'addrlen'},
    # # accept: [0: int sockfd, 1: struct sockaddr *addr, 2: socklen_t *addrlen]
    # angr.SIM_PROCEDURES['posix']['accept']().__class__: {0: 'sockfd', 1: 'addr', 2: 'addrlen'},
    # # accept4: [0: int sockfd, 1: struct sockaddr *addr, 2: socklen_t *addrlen, 3: int flags]
    # angr.SIM_PROCEDURES['posix']['accept4']().__class__: {0: 'sockfd', 1: 'addr', 2: 'addrlen', 3: 'flags'},
    # # sendto: [0: int sockfd, 1: const void *buf, 2: size_t len, 3: int flags, 4: const struct sockaddr *dest_addr, 5: socklen_t addrlen]
    # angr.SIM_PROCEDURES['posix']['sendto']().__class__: {0: 'sockfd', 1: 'buf', 2: 'len', 3: 'flags', 4: 'dest_addr', 5: 'addrlen'},
    # # listen: [0: int sockfd, 1: int backlog]
    # angr.SIM_PROCEDURES['posix']['listen']().__class__: {0: 'sockfd', 1: 'backlog'},
}

ban_lib_categories = {
    'filesystem': {
        BanLibraryFunctionRule('open'),
        BanLibraryFunctionRule('fopen'),
    },
    'network': {
        BanLibraryFunctionRule('socket'),
    },
}
