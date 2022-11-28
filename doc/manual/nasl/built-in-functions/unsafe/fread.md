# fread

## NAME

**fread** - read a whole file on the openvas-scanner host

## SYNOPSIS

*string* **fread**(0: *string*);

**fread** takes 1 unnamed argument

## DESCRIPTION

This function is used to read a whole file in one go on the openvas-scanner host. It is not necessary to open/close a file descriptor.

The first positional argument is of type *string* and is the path to the file.

## RETURN VALUE

content of file as *string*

## ERRORS

first positional argument is missing

unable to read file, see *G_FILE_ERROR* for more information

## SEE ALSO

**[fwrite(3)](fwrite.md)**