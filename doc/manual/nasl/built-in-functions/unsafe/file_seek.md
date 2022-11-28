# file_seek

## Name

**file_seek** - set offset for file operations

## SYNOPSIS

*int* **file_seek**(fp: *int*, offset: *int*);

**file_seek** takes 2 named arguments

## DESCRIPTION

This function takes a file descriptor and applies an offset for operations on the file.

*fp* is an *int* parameter. It is the file descriptor for the file to read from. It is returned by **[file_open(3)](file_open.md)**.

*offset* is an *int* parameter. It determines the offset

## RETURN VALUE

0 on success, NULL on error

## ERRORS

*fd* parameter is missing or negative

unable to apply the offset, see **lseek(2)** for more information

## SEE ALSO

**[file_open(3)](file_open.md)**
