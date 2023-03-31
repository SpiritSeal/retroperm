from angr import SimProcedure


class Rule:
    """
    The base class for all rules.
    :param is_whitelist: True if the rule is a whitelist.
    :param is_blacklist: True if the rule is a blacklist.
    :param simproc: The simproc this rule is associated with.
    """

    def __init__(self, is_whitelist: bool, is_blacklist: bool, simproc: SimProcedure, description: str = None):
        self.is_whitelist = is_whitelist
        self.is_blacklist = is_blacklist
        if is_whitelist and is_blacklist:
            raise ValueError('A rule cannot be both a whitelist and a blacklist.')
        self.simproc = simproc
        self.description = description

    def __str__(self):
        return self.__repr__() + '\nDescription: ' + self.description

    def __repr__(self):
        # Combine the above code into a single line
        return ("Whitelist" if self.is_whitelist else "Blacklist") + " rule for " + str(self.simproc)
