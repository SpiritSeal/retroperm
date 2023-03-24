import angr
from pathlib2 import Path


class perm_finder:
    '''
    Generate a list of permissions for a given binary
    :param executable: The path to the executable
    :param working_dir: The executable's working directory
    '''

    def __init__(self, executable: Path, working_dir: Path = None):
        self.executable = executable
        self.working_dir = working_dir if working_dir else executable.parent
