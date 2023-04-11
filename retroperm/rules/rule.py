import pprint
from typing import Dict, List
# from retroperm.project import ResolvedFunctionObject
import retroperm.project as rpp

class Rule:
    """
    The base class for all rules.
    """

    def __init__(self):
        ...

    # def validate_batch(self, resolved_data: Dict[str, rpp.ResolvedFunctionObject]) -> bool:
    #     """
    #     Validate the rule against the resolved data.
    #     """
    #     ...
    #
    # def validate(self, resolved_function: rpp.ResolvedFunctionObject) -> bool:
    #     """
    #     Validate the rule against a single resolved function.
    #     """
    #     ...

    def validate_batch(self, resolved_data: Dict) -> bool:
        """
        Validate the rule against the resolved data.
        """
        raise NotImplementedError

    def validate(self, resolved_function_obj) -> bool:
        """
        Validate the rule against a single resolved function.
        """
        raise NotImplementedError
