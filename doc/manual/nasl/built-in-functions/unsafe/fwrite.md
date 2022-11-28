# fwrite

## NAME

**fwrite** - write a file on the openvas-scanner host

## SYNOPSIS

*int* **fwrite**(data: *string*, file: *string*);

**fwrite** takes 2 named arguments

## DESCRIPTION

This function is used to write a file on the openvas-scanner host. It is not necessary to open/close a file descriptor. If the file already exists, it gets overwritten.

*data* is a *string* parameter. It contains the data, which is written into a file.

*file* is a *string* parameter. It contains the path to the file to write to.

## RETURN VALUE

number of bytes written to the file as *int*

## ERRORS

parameter *data* is missing

parameter *file* is missing

unable to write file, see *G_FILE_ERROR* for more information

## SEE ALSO

**[fread(3)](fread.md)**