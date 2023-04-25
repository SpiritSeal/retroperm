from .rule import Rule
from .data import ban_lib_categories
from typing import Dict


class BanCategoryRule(Rule):
    def __init__(self, category: str):
        self.banned_library = category
        self.rules = ban_lib_categories[category]
        super().__init__()

    def __repr__(self):
        return f"Ban Category {self.banned_library}"

    def validate(self, resolved_function_obj: Dict[str, object]):
        """
        Validate the rule list
        """
        violations = []
        for rule in self.rules:
            if not rule.validate(resolved_function_obj):
                violations.append(rule)
        if violations:
            return violations
        return False
