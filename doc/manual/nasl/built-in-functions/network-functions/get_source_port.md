# get_source_port

## NAME

**get_source_port** - get port of a opened socket

## SYNOPSIS

*int* **get_source_port**(0: *int*);

**socket_get_ssl_version** takes one positional argument.

## DESCRIPTION

This function gets the port information from a open socket connection. Its argument is:
0. an *int* representing the socket

## RETURN VALUE

The port number of the socket connection or *NULL* on error.

## ERRORS

- missing argument
- invalid socket
- unable to get socket information
