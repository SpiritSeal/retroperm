import sys
from pathlib import Path

import unittest

from retroperm.project import RetropermProject
from retroperm.rules import Rule
from retroperm.rules.filesystem_rule import FilesystemRule
from retroperm.rules.ban_library_function_rule import BanLibraryFunctionRule
from retroperm.rules.ban_category_rule import BanCategoryRule
from typing import List
import ast
from pprint import pformat

TEST_BINARIES = Path(__file__).parent / "executables"


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class TestProject(unittest.TestCase):

    def test_function_resolver(self):
        # return
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        resolved_data = retro_proj.resolve_abusable_functions()
        # print("resolved data", resolved_data)
        res_func = resolved_data['resolved_function_data']['open']
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
        res_func = resolved_data['resolved_function_data']['open']
        print(res_func.args_by_location[0x40122a]['filename'])

        my_rule_good = FilesystemRule('/home/mahaloz/.global.bsconf', 'filename', is_whitelist=True, is_dir=False)
        my_rule_bad = FilesystemRule('/etc/passwd', 'filename', is_whitelist=False, is_dir=False)
        retro_proj.init_rules([my_rule_good, my_rule_bad], override_default=True)
        output = retro_proj.validate_rules()
        print(output)

    def test_banhammer(self):
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")

        retro_proj.resolve_abusable_functions()

        ban_open = BanLibraryFunctionRule('open')
        # TODO: Ban Categories
        retro_proj.init_rules([ban_open], override_default=True)

        output = retro_proj.validate_rules()
        print(output)

    def test_category_banhammer(self):
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        retro_proj.resolve_abusable_functions()
        ban_filesystem = BanCategoryRule('filesystem')
        ban_network = BanCategoryRule('network')
        retro_proj.init_rules([ban_filesystem, ban_network], override_default=True)
        output = retro_proj.validate_rules()
        print(output)

    def test_bad_vst(self):
        def iterprint(header: str, payload: dict):
            print(bcolors.HEADER+header+bcolors.ENDC)
            for key, v in payload.items():
                if v.startswith("Failed"):
                    print(f'{bcolors.WARNING}{key}: {v}{bcolors.ENDC}')
                else:
                    print(f'{bcolors.OKGREEN}{key}: {v}{bcolors.ENDC}')
            pass

        import re

        def eval_flow(proj: RetropermProject, header: str):
            # Rules
            ban_filesystem = BanCategoryRule('filesystem')
            ban_network = BanCategoryRule('network')
            my_rule_good = FilesystemRule("/home/mahaloz/.global.bsconf", 'filename', is_whitelist=True, is_dir=False)
            my_rule_bad = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)

            rule_list = [ban_filesystem, ban_network, my_rule_good, my_rule_bad]
            proj.init_rules(rule_list, override_default=True)
            output = proj.validate_rules()
            print()
            iterprint(header, output)

            print()
            if output[ban_filesystem].startswith("Failed"):
                resolved_data = retro_proj_mal.resolve_abusable_functions()
                rfo = resolved_data['resolved_function_data']

                match_list = ast.literal_eval(re.findall(r'\[.*\]', output[my_rule_bad])[0])

                for match in match_list:
                    if match not in rfo:
                        continue
                    match_rfo = rfo[match]
                    vals = list(match_rfo.args_by_location.values())
                    print(bcolors.OKCYAN+str(vals)+bcolors.ENDC)

            return output

        retro_proj_clean = RetropermProject(TEST_BINARIES / "GoodArpeggiator.so.o")
        resolved_data_clean = retro_proj_clean.resolve_abusable_functions()

        retro_proj_mal = RetropermProject(TEST_BINARIES / "BadArpeggiator.so.o")
        resolved_data_mal = retro_proj_mal.resolve_abusable_functions()


        # Validation
        # rules = [ban_filesystem, ban_network, my_rule_bad, my_rule_good]
        eval_flow(retro_proj_clean, '`CleanVST` Rule Validation')
        eval_flow(retro_proj_mal, '`MalVST` Rule Validation')


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
