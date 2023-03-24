import angr
import pyvex
from utils import get_arg_locations, string_at_addr

class resolver:
    def resolve_args_of_call(self, proj, cfg, func_addr, call_addr):
        """
        Resolve the arguments that are passed to a function call
        """
        ...


if __name__ == '__main__':
    ...
