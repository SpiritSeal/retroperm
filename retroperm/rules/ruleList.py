# TODO: Yeet this

from typing import List
from rule import Rule


class RuleList(List[Rule]):
    """
    A list of rules.
    :param rules: The list of rules.
    """

    def __init__(self, rules: List[Rule], description: str = None):
        self.description = description
        super().__init__(rules)

    def __str__(self):
        return self.description + '\n' + super.__str__(self)


if __name__ == '__main__':
    # Create some rules
    rule1 = Rule(True, False, None, "This is Rule 1")
    rule2 = Rule(False, True, None, "This is Rule 2")
    rule3 = Rule(True, False, None, "This is Rule 3")

    # Create a rule list
    rule_list = RuleList([rule1, rule2, rule3], 'This is a rule list')

    # Print the rule list
    print(rule_list)
