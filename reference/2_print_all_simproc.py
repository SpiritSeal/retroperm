import inspect

import angr

class PrintSimProcedure(angr.SimProcedure):
    def run(self, *args, **kwargs):
        print(inspect.getmro(self.__class__))

def print_simprocedures():
    # Load the binary
    proj = angr.Project('../executables/open_example', auto_load_libs=False)
    for simproc in proj._sim_procedures.values():
        print(simproc)

if __name__ == "__main__":
    print_simprocedures()
