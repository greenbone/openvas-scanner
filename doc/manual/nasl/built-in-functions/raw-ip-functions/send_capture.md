# send_capture

## NAME

**send_capture** - read the next packet

## SYNOPSIS

*string* **send_capture**(interface: *string*, pcap_filter: *string*, timeout: *int*);

**send_capture** takes 3 named arguments.

## DESCRIPTION

This function is the same as **[pcap_next(3)](pcap_next.md)**.

- interface: network interface name, by default NASL will try to find the best one
- pcap_filter: BPF filter, by default it listens to everything
- timeout: timeout in seconds, 5 by default

## RETURN VALUE

Packet which was captured

## SEE ALSO

**[pcap_next(3)](pcap_next.md)**
