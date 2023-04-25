from typing import Dict, Set

from retroperm.rules import Rule
from angr import sim_procedure
import angr


class BanLibraryFunctionRule(Rule):
    def __init__(self, library: sim_procedure):
        self.banned_library = library
        super().__init__()

    def __repr__(self):
        return f"Banned Library {self.banned_library}"

    # def validate_batch(self, resolved_data: Dict):
    #     """
    #     Validate the rule against the resolved data.
    #     """
    #     raise NotImplementedError

    def validate(self, resolved_function_obj: Dict[str, object]):
        """
        Validate the rule against the provided libraries
        """
        active_symbols = resolved_function_obj['active_symbols']
        # active_symbols: Set[angr.knowledge_plugins.functions.function.Function]
        symbol_names = set([x.name for x in active_symbols])
        if self.banned_library in symbol_names:
            return False
        return True
        # raise NotImplementedError
