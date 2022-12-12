# pcap_next

## NAME

**pcap_next** - read the next packet

## SYNOPSIS

*string* **pcap_next**(interface: *string*, pcap_filter: *string*, timeout: *int*);

**pcap_next** takes 3 named arguments.

## DESCRIPTION

This function is the same as **[send_capture(3)](send_capture.md)**.

- interface: network interface name, by default NASL will try to find the best one
- pcap_filter: BPF filter, by default it listens to everything
- timeout: timeout in seconds, 5 by default

## RETURN VALUE

Packet which was captured

## SEE ALSO

**[send_capture(3)](send_capture.md)**
