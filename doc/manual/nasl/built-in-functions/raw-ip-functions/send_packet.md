# send_packet

## NAME

**send_packet** - send a list of IP packets to the scanned host

## SYNOPSIS

*string* **send_packet**(*string*..., length: *int*, pcap_active: *bool*, pcap_filter: *string*, pcap_timeout: *int*, allow_broadcast: *bool*);

**send_packet** takes 4 named and any number of positional arguments.

## DESCRIPTION

Send a list of packets, passed as unnamed arguments, with the option to listen to the answers.

The arguments are:
- Any number of packets to send
- length: default length of each every packet, if a packet does not fit, its actual size is taken instead
- pcap_active: option to capture the answers, TRUE by default
- pcap_filter: BPF filter used for the answers
- pcap_timeout: time to wait for the answers in seconds, 5 by default
- allow_broadcast: default FALSE

## RETURN VALUE

A block of all answers as a single string.
