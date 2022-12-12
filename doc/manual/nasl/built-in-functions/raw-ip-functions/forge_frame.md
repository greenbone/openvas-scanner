# forge_frame

## NAME

**forge_frame** - forge a datalink layer frame

## SYNOPSIS

*string* **forge_frame**(src_haddr: *string*, dst_haddr: *string*, ether_proto: *int*, payload: *data*);

**forge_frame** takes 4 named arguments.

## DESCRIPTION

This function forges a datalink layer frame.

*src_haddr*: is a *string* containing the source MAC address

*dst_haddr*: is a *string* containing the destination MAC address

*ether_proto*: is an *int* containing the ethernet type (normally given as hexadecimal). It is optional and its default value is 0x0800.
A list of Types can be e.g. looked up [here](https://en.wikipedia.org/wiki/EtherType).

*payload*: is any *data*, which is then attached as payload to the frame. 

## RETURN VALUE

The forged frame as binary *data*.
