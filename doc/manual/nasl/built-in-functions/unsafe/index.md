# "unsafe" Functions

## GENERAL

"unsafe" functions are working with the scanner host file system. It is possible to open, read and write files as well as run commands.

## TABLE OF CONTENT

- **[file_close](file_close.md)** - close a file descriptor
- **[file_open](file_open.md)** - opens a file descriptor
- **[file_read](file_read.md)** - read from a file
- **[file_seek](file_seek.md)** - set offset for file operations
- **[file_stat](file_stat.md)** - get size of a file
- **[file_write](file_write.md)** - writes data to a file
- **[find_in_path](find_in_path.md)** - searches a command in $PATH and returns TRUE if found, or FALSE if not. It takes one string argument (the command name)
- **[fread](fread.md)** - read a whole file on the openvas-scanner host
- **[fwrite](fwrite.md)** - write a file on the openvas-scanner host
- **[get_tmp_dir](get_tmp_dir.md)** - get a path to temporary directory
- **[pread](pread.md)** - runs a command on the host system
- **[unlink](unlink.md)** - removes a file on the openvas scanner host
