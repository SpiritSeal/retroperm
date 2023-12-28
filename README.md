# Retroperm
A platform-agnostic rule-based system resource usage deduction library for retroactively generating "permissions" used by executable programs from their compiled binaries.

In other words: A library to figure out what system resources (specific files, network call targets, IO, etc.) any executable (.exe, ELF, etc) may attempt to use when run. Define rules for the resources you would like to monitor as privacy violations and `retroperm` will return potential violations of those rules.

## Usage

Install Retroperm from PyPI

```sh
pip install retroperm
```

> WIP. See the [tests](./tests) directory for examples.

## Developer Install
```sh 
git clone git@github.com:SpiritSeal/retroperm.git
cd retroperm
pip3 install -e .
```

## Current limitations
> This version of Retroperm is built as a proof-of-concept and is limited by the rules and syscall definitions it has defined.
> In addition, large binaries take excessive amounts of time to process due to the unoptimized manner in which this project leverages angr's Calling Convention Analysis.
> A partial optimization of this library is planned for December 2023. Feel free to reach out to `yssaketh[at]gmail[dot]com` if you are interested in contributing!
