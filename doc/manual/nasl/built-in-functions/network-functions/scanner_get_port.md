# scanner_get_port

## NAME

**scanner_get_port** - walks through the list of open ports

## SYNOPSIS

*any* **scanner_get_port**(*int*);

**scanner_get_port** takes a single unnamed argument, the index.

## DESCRIPTION

Walks through the list of open ports.
If the plugin is a port scanner, it needs to report the list of open ports back to openvas scanner, and it also needs to know which ports are to be scanned.


## RETURN VALUE

Returns a port number or 0 when the end of the list if reached.

## ERRORS

Index should be 0 the first time you call i
