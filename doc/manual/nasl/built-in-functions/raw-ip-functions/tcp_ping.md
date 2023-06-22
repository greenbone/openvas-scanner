# tcp_ping

## NAME

**tcp_ping** - Launches a TCP ping against the target host

## SYNOPSIS

*bool* **tcp_ping**(port: *int*);

**tcp_ping** takes 1 named argument.

## DESCRIPTION

This function tries to open a TCP connection and sees if anything comes back (SYN/ACK or RST).

Its argument is:
- port: port for the ping

## RETURN VALUE

TRUE on success, FALSE on failure
