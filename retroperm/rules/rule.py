from ..project import RetropermProject


class Rule:
    """
    The base class for all rules.
    """

    def __init__(self):
        ...

    def attach_to_project(self, project: RetropermProject):
        if project.rules is None:
            project.rules = {
                "rulelist": []
            }
        project.rules["rulelist"].append(self)
