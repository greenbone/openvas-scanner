# get_icmp_v6_element

## NAME

**get_icmp_v6_element** - Get an ICMP element from a IPv6 datagram.

## SYNOPSIS

*int* **get_icmp_v6_element**(icmp: *string*, element: *string*);

**get_icmp_v6_element** It takes two named.


## DESCRIPTION

Get an ICMP element from a IPv6 datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:

- icmp: is the IPv6 datagram (not the ICMP part only).
- element: is the name of the field to get
  
Valid ICMP elements to get are:

- icmp_id
- icmp_code
- icmp_type
- icmp_seq
- icmp_chsum
- icmp_data


## RETURN VALUE

Returns an ICMP element from a IP datagram.

## ERRORS

- Missing 'icmp' parameter.
- Missing 'element' parameter.
- Element is not a valid element to get.
