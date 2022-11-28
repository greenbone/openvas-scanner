# file_close

## NAME

**file_close** - close a file descriptor

## SYNOPSIS

*Optional(int)* **file_close**(0: *int*);

**file_close** takes one unnamed argument.

## DESCRIPTION

This function is used to close an opened file descriptor.

The first positional argument contains the file descriptor as an *int* returned by **[file_open(3)](file_open.md)**.

## RETURN VALUE

Either 0 on success or *NULL* on failure

## ERRORS

first positional argument is either missing or negative

closing the file descriptor failed

## SEE ALSO

**[file_open(3)](file_open.md)**
