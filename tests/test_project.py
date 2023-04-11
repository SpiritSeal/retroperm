import sys
from contextlib import redirect_stderr
from pathlib import Path

import unittest

from retroperm.project import RetropermProject
from retroperm.rules.filesystem_rule import FilesystemRule

TEST_BINARIES = Path(__file__).parent / "executables"


class TestProject(unittest.TestCase):
    def test_function_resolver(self):
        # return
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        resolved_data = retro_proj.resolve_abusable_functions()
        # print("resolved data", resolved_data)
        res_func = resolved_data['open']
        print("open func", res_func.args_by_location)

        assert res_func.args_by_location[0x40120c]['filename'] == '/etc/passwd'
        assert res_func.args_by_location[4198954]['filename'] == '/home/mahaloz/.global.bsconf'

    def test_load_rules(self):
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        retro_proj.resolve_abusable_functions()

        my_rule = FilesystemRule("/home/mahaloz/.config/", is_whitelist=True, is_dir=True)
        retro_proj.init_rules([my_rule], override_default=True)
        output = retro_proj.validate_rules()
        print(output)


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
