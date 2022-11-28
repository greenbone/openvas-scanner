# file_read

## NAME

**file_read** - read from a file

## SYNOPSIS

*string* **file_read**(fp: *int*, length: *int*);

**file_read** takes two named arguments

## DESCRIPTION

This function is used to read data from a file.

*fp* is an *int* parameter. It is the file descriptor for the file to read from. It is returned by **[file_open(3)](file_open.md)**.

*length* is an *int* parameter. It determines the length of the data to read from the file

With the function **[file_seek(3)](file_seek.md)** an offset can be set from where to start reading the file.

## RETURN VALUE

Data from the file as *string*

## ERRORS

missing or negative *fp* argument

## EXAMPLES

**1**: Open file descriptor, read file, close it
```cpp
fd = file_open(name: "foo/bar.txt", mode: "w");
txt = file_read(fp: fd, length: 10);
file_close(fd);
# do some stuff with txt
```

## SEE ALSO

**[file_open(3)](file_open.md)**, **[file_seek(3)](file_seek.md)**
