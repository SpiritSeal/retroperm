from .rule import Rule


class ArgumentRule(Rule):
    def __init__(self, arg_cat: str):
        self.arg_cat = arg_cat
        super().__init__()
