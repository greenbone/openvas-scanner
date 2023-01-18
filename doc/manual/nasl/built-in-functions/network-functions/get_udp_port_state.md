# get_udp_port_state

## NAME

**get_udp_port_state** - get a udp port state.

## SYNOPSIS

*any* **get_udp_port_state**(*int*);

**get_udp_port_state** takes one single unnamed argument, the port.

## DESCRIPTION

As some TCP ports may be in an unknown state because they were not scanned, the behavior of this function may be modified by the “consider unscanned ports as closed” global option. When this option is reset (the default), get_udp_port_state will return TRUE on unknown ports; when it is set, get_udp_port_state will return FALSE.

Note that UDP port scanning may be unreliable.

## RETURN VALUE

Returns TRUE if it is open and FALSE otherwise.

## ERRORS
 
## EXAMPLES

**1**: Get and display the state of the given port.
```cpp
st = get_udp_port_state(port);
display(st);

```

## SEE ALSO

**[display(3)](display.md)**
