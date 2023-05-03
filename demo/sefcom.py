from pathlib import Path
import logging
import code
TEST_BINARIES = Path('/home/spyre/PycharmProjects/retroperm/tests/executables/')
logging.getLogger("cle").setLevel(logging.ERROR)
mal_VST_loc = TEST_BINARIES / 'BadArpeggiator.so.o'
clean_VST_loc = TEST_BINARIES / 'GoodArpeggiator.so.o'
'''Demo handler code above, main usage code below'''

from retroperm.project import RetropermProject
from retroperm.rules.filesystem_rule import FilesystemRule
from retroperm.rules.ban_category_rule import BanCategoryRule



def simplified_showcase():
    retro_proj = RetropermProject(TEST_BINARIES / "BadArpeggiator.so.o")
    resolved_data = retro_proj.resolve_abusable_functions()

    # Rules
    ban_filesystem = BanCategoryRule('filesystem')
    ban_network = BanCategoryRule('network')
    config_rule = FilesystemRule("/home/spyre/.global.bsconf", 'filename', is_whitelist=True, is_dir=False)
    etc_passwd_rule = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)
    etc_shadow_rule = FilesystemRule("/etc/shadow", 'filename', is_whitelist=False, is_dir=False)

    rule_list = [ban_filesystem, ban_network, config_rule, etc_passwd_rule, etc_shadow_rule]
    retro_proj.init_rules(rule_list, override_default=True)
    output = retro_proj.validate_rules()
    print(output, '\n')
    code.interact(local=locals())


if __name__ == '__main__':
    simplified_showcase()

