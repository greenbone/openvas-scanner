# join_multicast_group

## NAME

**join_multicast_group** - join a multicast group.

## SYNOPSIS

*any* **join_multicast_group**(*string*);

**join_multicast_group** takes a single unnamed argument, an IP multicast address

## DESCRIPTION

Join the multicast group given by the IP multicast address argument. If the group was already joined, the function joins increments an internal counter

## RETURN VALUE

Return TRUE on success, Null on error.

## ERRORS

- Invalid parameter
- Missing parameter
- Socket error
- Set socket error
