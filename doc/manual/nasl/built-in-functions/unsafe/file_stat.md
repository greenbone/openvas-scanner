# file_stat

## NAME

**file_stat** - get size of a file

## SYNOPSIS

*int* **file_stat**(0: *string*);

**file_stat** takes one positional argument

## DESCRIPTION

This function is used to get the size of a file.

The first unnamed argument is the path to the file as *string*

## RETURN VALUE

The size of the file as *int* or *NULL* on failure

## ERRORS

first positional argument is missing

## NOTES

Currently it is not possible to get the cause of the failure

## SEE ALSO

**[file_open(3)](file_open.md)**
