import sys
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
        assert res_func.args_by_location[0x40122a]['filename'] == '/home/mahaloz/.global.bsconf'

    def test_load_rules(self):
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        retro_proj.resolve_abusable_functions()

        my_rule_good = FilesystemRule("/home/mahaloz/.global.bsconf", 'filename', is_whitelist=True, is_dir=False)
        my_rule_bad = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)
        retro_proj.init_rules([my_rule_good, my_rule_bad], override_default=True)
        output = retro_proj.validate_rules()
        assert output[my_rule_good] == 'Passed'
        assert output[my_rule_bad] == 'Failed on [\'open\']'

    def test_debug_testcase(self):
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        resolved_data = retro_proj.resolve_abusable_functions()
        # print("resolved data", resolved_data)
        res_func = resolved_data['open']
        print(res_func.args_by_location[0x40122a]['filename'])

        my_rule_good = FilesystemRule('/home/mahaloz/.global.bsconf', 'filename', is_whitelist=True, is_dir=False)
        my_rule_bad = FilesystemRule('/etc/passwd', 'filename', is_whitelist=False, is_dir=False)
        retro_proj.init_rules([my_rule_good, my_rule_bad], override_default=True)
        output = retro_proj.validate_rules()
        print(output)

    def test_banhammer(self):
        pass


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
