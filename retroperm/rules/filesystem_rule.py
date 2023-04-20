from typing import Dict
# from .rule import Rule
from .argument_rule import ArgumentRule
from pathlib2 import Path
import pathlib2 as pathlib

from ..project import ResolvedFunctionObject


class FilesystemRule(ArgumentRule):
    """
    Filesystem rules.
    """

    def __init__(self,
                 location: str | Path,
                 arg_cat: str,  # argument_category
                 is_whitelist: bool,
                 is_dir: bool):
        super().__init__(arg_cat)
        self.location = location
        self.is_whitelist = is_whitelist
        self.is_dir = is_dir

    def __repr__(self):
        # return f'FilesystemRule({self.location=}, {self.arg_cat=}, {self.is_whitelist=}, {self.is_dir=})'
        # I just want location and whitelist status
        # return f'FilesystemRule(\'{self.location}\' is {"whitelisted" if self.is_whitelist else "blacklisted"})'
        # Format as "Whitelist: /etc/passwd"
        return f'{"Whitelist" if self.is_whitelist else "Blacklist"} {self.location}'

    # def validate(self, resolved_data: Dict[str, ResolvedFunctionObject]) -> Dict:
    def validate(self, resolved_project_data: Dict[str, object]) -> Dict:
        """
        Validate the rule against the resolved data.
        """
        resolved_function_data = resolved_project_data['resolved_function_data']
        output: dict[str, bool] = {}
        for key, rfo in resolved_function_data.items():
            if self.validate_rfo(rfo):
                # Redundant for now, but will maybe be useful later
                output[key] = True
                # print(f'Rule {self} passed on {key}!')
            else:
                output[key] = False
                # print(f'Rule {self} failed on {key}!')
        return output

    def validate_rfo(self, rfo: ResolvedFunctionObject) -> bool:
        """
        Validate the rule against a single resolved function.
        """
        for addr, res_args in rfo.args_by_location.items():
            if self.arg_cat not in res_args:
                continue
            if self.arg_cat is 'filename':
                if self.is_whitelist:
                    if self.is_dir:
                        pass
                    if self.location == res_args[self.arg_cat]:
                        return True
                    else:
                        continue
                else:
                    if self.is_dir:
                        pass
                    if self.location == res_args[self.arg_cat]:
                        return False
                    else:
                        continue
            else:
                raise NotImplementedError
        # If you don't show up in the args, you're not a problem
        return True
