from .rule import Rule
from angr import SimProcedure
from pathlib2 import Path
import pathlib2 as pathlib


class FilesystemRule(Rule):
    """
    Filesystem rules.
    """

    empty_whitelist = {
        "dirs": [],
        "files": []
    }

    # blacklist = {
    #     "dirs": [],
    #     "files": []
    # }

    def __init__(self,
                 location: str | Path,
                 is_whitelist: bool,
                 is_dir: bool):
        self.location = location
        self.is_whitelist = is_whitelist
        self.is_dir = is_dir