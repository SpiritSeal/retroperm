# Steps for Reference Script 3: Reverse Hook Arglocation

1. Find all calls and resolve them to their symbols
2. Run CCCA on the project
3. Use the symbols to lookup the simprocs using `proj.symbol_hooked_by(SYMBOL)`
    - If the simproc doesn't exist, that means that it isn't a lib function and we don't care abt it.
4. Lookup dictionary that associates the class's of simprocs with their "important argument numbers"
    - i.e. arg 0, arg 1, etc.
5. Get the registers associated with the function
6. Synthesize info from previous two steps to get a list of registers that can contain important/ abusable values


## End result: 
- We know what pre-call registers need to be resolved in order to get the (important) values that were passed into the library call