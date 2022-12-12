# send_arp_request

## NAME

**send_arp_request** - send an arp request to the scanned host

## SYNOPSIS

*string* **send_arp_request**(pcap_timeout: *int*);

**send_arp_request** Takes 1 named argument

## DESCRIPTION

This function creates a datalink layer frame for an arp request and sends it to the currently scanned host.

It takes the following argument:
- pcap_timeout: time to wait for answer in seconds, 5 by default

## RETURN VALUE

The answer of the arp request or *NULL* on error.

## ERRORS

- Unable to send frame
- No answer received
