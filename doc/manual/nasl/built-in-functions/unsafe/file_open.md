# file_open

## NAME

**file_open** - opens a file descriptor

## SYNOPSIS

*int* **file_open**(name: *string*, mode: *string*);

**file_open** takes two named arguments.

## DESCRIPTION

This function is used to open a file descriptor to be able to either read or write to a file on the host system.

*name* is a *string* parameter. It contains the path of the file.

*mode* is a *string* parameter. It contains the mode in which the file is opened. There are 5 modes:
- r: read only
- w: write only + create
- w+: write only + truncate + create
- a: write only + append + create
- a+: read and write + append + create

After done with the file, the descriptor hast to be closed with **[file_close(3)](file_close.md)**.

## RETURN VALUE

*int* representing the file descriptor or *NULL* on failure

## ERRORS

parameter *name* is missing

parameter *mode* is missing

unable to open file descriptor, see **open(2)** for further information

unable to retrieve file stats, see **stat(2)** for further information

## SEE ALSO

**[file_close(3)](file_close.md)**
