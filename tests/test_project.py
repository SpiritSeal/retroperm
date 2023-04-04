import sys
from pathlib import Path

import unittest

from retroperm.project import RetropermProject

TEST_BINARIES = Path(__file__).parent / "executables"


class TestProject(unittest.TestCase):
    def test_function_resolver(self):
        retro_proj = RetropermProject(TEST_BINARIES / "open_example")
        resolved_data = retro_proj.resolve_abusable_functions()
        res_func = resolved_data['open']
        
        assert res_func.args_by_location[0x40120c]['filename'] == '/etc/passwd'
        assert res_func.args_by_location[4198954]['filename'] == '/home/mahaloz/.global.bsconf'


if __name__ == "__main__":
    unittest.main(argv=sys.argv)
