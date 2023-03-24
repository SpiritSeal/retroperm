from rule import Rule
from angr import SimProcedure
from pathlib2 import Path
import pathlib2 as pathlib

class FilesystemRule(Rule):
    """
    Filesystem rules.
    :param is_whitelist: True if the rule is a whitelist.
    :param is_blacklist: True if the rule is a blacklist.
    :param simproc: The simproc this rule is associated with.
    :param path: The path this rule is associated with.
    :param operation: The filesystem operation (r/w/o) this rule is associated with.
    """

    def __init__(self, is_whitelist: bool, is_blacklist: bool, simproc: SimProcedure, path: Path, operation: str):
        super().__init__(is_whitelist, is_blacklist, simproc)
        self.path = path
        self.operation = operation
