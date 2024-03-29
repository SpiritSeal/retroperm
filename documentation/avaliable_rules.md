# List of implemented rule types:

## [FilesystemRule](../retroperm/rules/filesystem_rule.py) - Check if specific file is accessed or written to by binary:

### Arguments
- `path` - Path to file to check
- `rule_type` - Generalized target parameter; currently only supports `filename`
- `is_whitelist` - Use true if you plan on running a whitelist check; use false if you plan on running a blacklist check
- `is_dir` - If true, treat `path` as a directory instead of a file

### Example Usage:
```py
my_rule = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)
```

### Limitations
- Currently only resolves one level of reaching definitions
    - This means that if a value is assigned to a variable, and then that variable is assigned to another variable, it will not be detected unless the compiler optimizes the code to remove the middle variable
    - This is a limitation of the current implementation, and will be fixed in the future

## [BanCategoryRule](../retroperm/rules/ban_category_rule.py) - Blacklist full category of system and library calls:
> Intended to be a more generic "catch-all" rule type that requires less rigorous internal definitions.

### Arguments
- `category` - Category of system calls to ban
    - Options:
        - `filesystem`
        - `network`
        - [Feel free to add more!](../retroperm/rules/data.py)

### Example Usage:
```py
my_rule = BanCategoryRule('network')
```

## [BanLibraryFunctionRule](../retroperm/rules/ban_library_function_rule.py) - Blacklist specific system or library function calls given angr simprocedure name:

### Arguments
- `library` - system or library call to blacklist

### Example Usage:
```py
my_rule = BanLibraryFunctionRule('open')
```

## Other Planned Rule Types:
- NetworkRule - Check if binary makes network connections to specific IP addresses or domains
- ProcessRule - Check if binary spawns specific processes

