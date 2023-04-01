from retroperm.project import RetropermProject

retro_proj = RetropermProject("../executables/open_example")
resolved_data = retro_proj.resolve_abusable_functions()
print(resolved_data)

# output:
# {'angr.procedures.posix.open.open': [<ResolvedFunctionData: open@[0xdeadbeef]>,
#                                      <ResolvedFunctionData: open@[0xcafebabe]>,
#                                      ...]}

# res_func = resolved_data['open']
# print(res_func.args_by_location)

# output:
# [0xdeadbeef: {"filename": "/etc/passwd"}, 0xcafebabe: {"filename": "/home/mahaloz"}]
