# nasl-builtin-utils

Contains the necessary traits and helper functions to create builtin functions.

To register your function you have to add it into the context of an interpreter.
Usually that is done by adding it to [nasl-builtin-std::nasl_std_functions] so that it is registered on an default interpreter run.
