# get_ip_element

## NAME

**get_ip_element** - extracts a field from a IP datagram.

## SYNOPSIS

*int* **get_ip_element**(ip: *string*, element: *string*);

**get_ip_element** It takes two named parameters.


## DESCRIPTION

Get an ICMP element from a IP datagram. It returns a data block or an integer, according to the type of the element. Its arguments are:

- ip: is the IP datagram.
- element: is the name of the field to get
  
Valid IP elements to get are:

- ip_v
- ip_id
- ip_hl
- ip_tos
- ip_len
- ip_off
- ip_ttl
- ip_p
- ip_sum
- ip_src
- ip_dst

For more information look into **[forge_ip_packet](forge_ip_packet.md)**

## RETURN VALUE
Returns an IP element from a IP datagram.


## ERRORS

- no valid 'ip' argument
- no valid 'element' argument
- unknown element

## SEE ALSO

**[forge_ip_packet](forge_ip_packet.md)**
