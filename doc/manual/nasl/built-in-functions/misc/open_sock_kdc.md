# open_sock_kdc

## NAME

**open_sock_kdc** - open a kdc socket

## SYNOPSIS

*int* **open_sock_kdc**();

**open_sock_kdc** takes no arguments.

## DESCRIPTION

This function takes no arguments, but it is mandatory that keys are set. The following keys are required:
- Secret/kdc_hostname
- Secret/kdc_port
- Secret/kdc_use_tcp

## RETURN VALUE

An *int* representing the socket or *NULL* on error.

## Error

- any of the required keys is missing
- unable to open socket
