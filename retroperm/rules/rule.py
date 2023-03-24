from angr import SimProcedure


class Rule:
    """
    The base class for all rules.
    :param is_whitelist: True if the rule is a whitelist.
    :param is_blacklist: True if the rule is a blacklist.
    :param simproc: The simproc this rule is associated with.
    """

    def __init__(self, is_whitelist: bool, is_blacklist: bool, simproc: SimProcedure):
        self.is_whitelist = is_whitelist
        self.is_blacklist = is_blacklist
        self.simproc = simproc
