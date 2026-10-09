# openvas-nasl-lint(1)

## NAME

openvas-nasl-lint - OpenVAS standalone NASL linter

## SYNOPSIS

**openvas-nasl-lint** \[*option*...\] *nasl_file*...

## DESCRIPTION

OpenVAS is a framework of several services and tools offering a
comprehensive and powerful vulnerability scanning and vulnerability
management solution.

**openvas-nasl-lint** is linter targeted at the NASL language.

## OPTIONS

These programs follow the usual GNU command line syntax, with long
options starting with two dashes (\`-\'). A summary of options is
included below.

**-h**, **--help**

:   Show summary of options.

**-d**, **--debug**

:   Output debug log messages.

**-l** *file*, **--nvt-list** *file*

:   Process files from *file*.

**-i** *dir*, **--include-dir *dir*

:   Search for includes in *dir*.

**--strict-includes**

:   Enable check for strict include order.


## SEE ALSO

**[openvas(8)](../openvas/openvas.md)**, **[openvas-nasl(1)](openvas-nasl.md)**
