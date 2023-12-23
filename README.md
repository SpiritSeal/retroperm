# Retroperm
A platform-agnostic system resource usage deduction library for retroactively generating "permissions" used by executable programs from their compiled binaries.

## Developer Install
```sh 
git clone git@github.com:SpiritSeal/retroperm.git
cd retroperm
pip3 install -e .
```

## Usage
> WIP. See the [tests](./tests) directory for examples.

## Current limitations
> This version of Retroperm is built as a proof-of-concept and is limited by the rules and functions it has defined.
> In addition, large binaries take excessive amounts of time to process due to the unoptimized manner in which this project leverage's angr's Calling Convention Analysis.
> A partial optimization of this library is planned for December 2023. Feel free to reach out to `yssaketh[at]gmail[dot]com` if you are interested in contributing!
