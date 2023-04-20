import pprint
from typing import Dict, List
# from retroperm.project import ResolvedFunctionObject
import retroperm.project as rpp


class Rule:
    """
    The base class for all rules.
    """

    def __init__(self):
        # self.arg_cat = arg_cat
        pass

    # def validate_batch(self, resolved_data: Dict):
    #     """
    #     Validate the rule against the resolved data.
    #     """
    #     raise NotImplementedError

    def validate(self, resolved_function_obj):
        """
        Validate the rule
        """
        raise NotImplementedError
