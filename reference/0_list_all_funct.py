import angr


# List all functions in binary
def list_all_functions(prog):
    proj = angr.Project(prog, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    for func in cfg.kb.functions.values():
        print("Function name: ", func.name)
        print("> Start address: ", func.addr)
        print("> Is it a library function? ", func.is_plt)
        print("> Is it a syscall? ", func.is_syscall)
        print()


# main
if __name__ == '__main__':
    program = "../executables/fauxware"
    list_all_functions(program)
