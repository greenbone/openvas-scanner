# OpenVAS Documentation (WORK IN PROGRESS)
**Project Title**

OpenVAS Project Documentation

**Project Description**

This repository contains the documentation for the OpenVAS project, which consists of three main parts:

Doxygen: The Doxygen documentation serves as the documentation for the internal C library of the project. To build the Doxygen documentation, run the following command: `make doxygen-full`.

Man: In the man folder, you can find the man pages for the project's executables. These man pages are automatically installed when calling `make install`. Additionally, you have the option to generate man pages for the built-in NASL functions. To generate these NASL man pages, use the command: `make nasl-man`. Please note that the NASL man pages are not automatically installed, and you need to have pandoc installed in order to generate them.

Manual: The general-purpose manual of the OpenVAS project can be generated using the command: `make manual`. This manual provides comprehensive information about the OpenVAS project, including the NASL documentation. Generating the manual also requires pandoc to be installed.

