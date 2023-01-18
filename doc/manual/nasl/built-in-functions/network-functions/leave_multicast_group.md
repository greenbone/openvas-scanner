# leave_multicast_group

## NAME

**leave_multicast_group** - leaves a multicast group.

## SYNOPSIS

*any* **leave_multicast_group**(*string*);

**leave_multicast_group** takes a single unnamed argument, an IP multicast address.

## DESCRIPTION

Leaves a multicast group. Note that if *join_multicast_group* was called several times, each call to *leave_multicast_cast* only decrements a counter; the group is left when the counter reaches 0.


## RETURN VALUE

Return FAKE_CELL, or NULL on error

## ERRORS

- Invalid parameter
- Missing parameter
- Never join to the group

## EXAMPLES

**1**: Leave a multicast group
```cpp
join_multicast_group("224.0.0.1");
join_multicast_group("224.0.0.1");
leave_multicast_group("224.0.0.1");
leave_multicast_group("224.0.0.1");
```

## SEE ALSO

**[join_multicast_group(3)](join_multicast_group.md)**
