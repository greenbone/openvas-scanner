# file_write

## NAME

**file_write** - writes data to a file

## SYNOPSIS

*int* **file_write**(fp: *int*, data: *string*);

## DESCRIPTION

This function writes to a opened file. In order to be able to write to a file it has to be opened with **[file_open(3)](file_open.md)** before.

*fp* is an *int* parameter. It is the file descriptor for the file to write into

*data* is a *string* parameter. It is the data, which is written into the file

## RETURN VALUE

number of written bytes, *NULL* on error and 0 on failure

## ERRORS

*fp* or *data* argument is missing

unable to write data, see **write(2)** for more information

## EXAMPLES

**1**: Open file descriptor, write file, close it
```cpp
fd = file_open(name: "foo/bar.txt", mode: "w");
file_write(fp: fd, data: "put some useful text in here");
file_close(fd);
```

## SEE ALSO

**[file_open(3)](file_open.md)**