from typing import Dict

from retroperm.rules import Rule
from angr import sim_procedure


class BanLibraryFunctionRule(Rule):
    def __init__(self, library: sim_procedure):
        self.banned_library = library
        super().__init__()

    def __repr__(self):
        return f"Banhammer {self.banned_library}"

    def validate_batch(self, resolved_data: Dict):
        """
        Validate the rule against the resolved data.
        """
        raise NotImplementedError

    def validate(self, resolved_function_obj):
        """
        Validate the rule against a single resolved function.
        """
        raise NotImplementedError
