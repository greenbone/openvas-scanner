# get_tcp_port_state

## NAME

**get_tcp_port_state** - Get a port state

## SYNOPSIS

*any* **get_tcp_port_state**(*int*);

**get_tcp_port_state** takes one single unnamed argument, the port.

## DESCRIPTION

As some TCP ports may be in an unknown state because they were not scanned, the behavior of this function may be modified by the “consider unscanned ports as closed” global option. When this option is reset (the default), get_tcp_port_state will return TRUE on unknown ports; when it is set, get_tcp_port_state will return FALSE.
This function is the same as **[get_port_state(3)](get_port_state.md)**.

## RETURN VALUE

Returns TRUE if it is open and FALSE otherwise.

## SEE ALSO

**[get_port_state(3)](get_port_state.md)**
