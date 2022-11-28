# get_tmp_dir

## NAME

**get_tmp_dir** - get a path to temporary directory

## SYNOPSIS

*string* **get_tmp_dir**();

## DESCRIPTION

This function gets the directory to use for temporary files.

On UNIX, this is taken from the *TMPDIR* environment variable. If the variable is not set, *P_tmpdir* is used, as defined by the system C library. Failing that, a hard-coded default of "/tmp" is returned.

If the access to this directory is denied, the function fails and *NULL* is returned.

This is useful to write temporary date onto the scanner host system.

## RETURN VALUE

Path to the directory as *string* or *NULL* on failure

## ERRORS

no access to the temporary directory

## EXAMPLES

**1**: Get path to tmp directory and create file
```cpp
path = get_tmp_dir();
if(path) {
    fd = file_open(name: path, mode: "w");
    # do some stuff with new file
    file_close(fd)
}
```

## SEE ALSO

**[file_open(3)](file_open.md)**, **[file_close(3)](file_close.md)**