from retroperm.project import RetropermProject

retro_proj = RetropermProject("./path/to/binary")
resolved_data = retro_proj.resolve_abusable_functions()
print(resolved_data)

# output:
# {'open': [<ResolvedFunction: open@[0xdeadbeef]>,
#           <ResolvedFunction: open@[0xdeadbeef]>,
#           ...]}

res_func = resolved_data['open']
print(res_func.args_by_location)

# output:
# [0xdeadbeef: {"filename": "/etc/passwd"}, 0xcafebabe: {"filename": "/home/mahaloz"}]
