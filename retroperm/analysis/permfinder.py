import angr
from pathlib2 import Path


class PermFinder:
    """
    Generate a list of permissions for a given binary
    :param executable: The path to the executable
    :param working_dir: The executable's working directory
    """
    def __init__(self, executable: Path | str, working_dir: Path = None):
        # Convert to Path
        if isinstance(executable, str):
            executable = Path(executable)
        self.executable = executable
        self.working_dir = working_dir if working_dir else executable.parent
        self.project = angr.Project(str(executable), auto_load_libs=False)


if __name__ == '__main__':
    output = PermFinder('../../executables/open_example')
    print(output)
