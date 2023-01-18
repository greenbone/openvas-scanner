# get_port_state

## NAME

**get_port_state** - get a port state

## SYNOPSIS

*any* **get_port_state**(*int*);

**get_port_state** takes one single unnamed argument, the port.

## DESCRIPTION

As some TCP ports may be in an unknown state because they were not scanned, the behavior of this function may be modified by the “consider unscanned ports as closed” global option. When this option is reset (the default), get_port_state will return TRUE on unknown ports; when it is set, get_port_state will return FALSE.

## RETURN VALUE

Returns TRUE if it is open and FALSE otherwise.
