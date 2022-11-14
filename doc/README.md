# OpenVAS Documentation (WORK IN PROGRESS)
The new documentation is still a WORK IN PROGRESS!!

The documentation of this project contains three parts:
1. Doxygen
It is used as a documentation of the internal c library. To build the doxygen documentation call `make doxygen-full`.

2. Man
In the man folder you can find man pages of the executables of the project. These are automatically installed when calling `make install`. Additionally it is possible to generate man pages of the built-in nasl functions. These can be generated with `make nasl-man`. Be aware that those are currently not automatically installed and pandoc is required in order to be able to generate those.

3. Manual
It is also possible to generate a general purpose manual of the openvas project. The manual can be generated with `make manual` and contains various information about the OpenVAS project including the NASL-documentation. Also for this pandoc is required.
