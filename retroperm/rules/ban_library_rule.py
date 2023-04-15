from retroperm.rules import Rule
from angr import sim_procedure


class BanLibraryRule(Rule):
    def __init__(self, library: sim_procedure):
        self.banned_library = library
        super().__init__()
