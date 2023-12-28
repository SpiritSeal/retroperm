# Retroperm
A platform-agnostic rule-based system resource usage deduction library for retroactively generating "permissions" used by executable programs from their compiled binaries.

In other words: A library to figure out what system resources (specific files, network call targets, IO, etc.) any executable (.exe, ELF, etc) may attempt to use when run. Define rules for the resources you would like to monitor and `retroperm` will return potential violations of those rules.

## Usage

Install Retroperm from PyPI

```sh
pip install retroperm
```

## Initialize Retroperm Project

```py
from retroperm import Retroperm

retroperm_proj = Retroperm("path/to/binary")
```

## Initialize Rules

> [Full list of implemented rule types](./documentation/avaliable_rules.md)

```py
from retroperm.rules.filesystem_rule import FilesystemRule
from retroperm.rules.ban_library_function_rule import BanLibraryFunctionRule

# Define a rule that blacklists all filesystem access to /etc/passwd
blacklist_etc_passwd_rule = FilesystemRule("/etc/passwd", 'filename', is_whitelist=False, is_dir=False)

# Define a rule that blacklists all network access
blacklist_all_network_calls_rule = BanCategoryRule('network')

rule_list = [blacklist_etc_passwd_rule, blacklist_all_network_calls_rule]

retroperm_proj.load_rules(rule_list)
```

## Run Retroperm Analysis

```py
results = retroperm_proj.validate_rules()
print(results)
```

> See [tests/test_project.py](./tests/test_project.py) for more examples.

## Developer Install
```sh 
git clone git@github.com:SpiritSeal/retroperm.git
cd retroperm
pip3 install -e .
```

## Library limitations
> This version of Retroperm is built as a proof-of-concept and is limited by the rules and syscall definitions it has defined.
> In addition, large binaries take excessive amounts of time to process due to the unoptimized manner in which this project leverages angr's Calling Convention Analysis.
