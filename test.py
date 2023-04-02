from retroperm.rules import Rule
from retroperm.project import RetropermProject


def test_function_resolver():
    retro_proj = RetropermProject("./executables/open_example")
    resolved_data = retro_proj.resolve_abusable_functions()
    print(resolved_data)

    # output:
    # {'open': <ResolvedFunction: open@[0xdeadbeef, ...]>}

    res_func = resolved_data['open']
    print(res_func.args_by_location)

    # output:
    # {0xdeadbeef: {"filename": "/etc/passwd"}, 0xcafebabe: {"filename": "/home/mahaloz"}}


def test_rule():
    print(f"Rules: {Rule}")


if __name__ == '__main__':
    test_function_resolver()
