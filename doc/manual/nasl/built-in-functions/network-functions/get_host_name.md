# get_host_name

## NAME

**get_host_name** - get_host_names the given socket

## SYNOPSIS

*any* **get_host_name**(*FD*);

**get_host_name** takes single unnamed argument, the socket file descriptor to be get_host_name.

## DESCRIPTION

This function get the hostname for a given socket.

## RETURN VALUE

Return FAKE_CELL, or Null on error

## ERRORS

- Invalid socket value
 