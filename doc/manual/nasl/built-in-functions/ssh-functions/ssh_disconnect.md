# ssh_disconnect

## NAME

**ssh_disconnect** - disconnect an open SSH connection

## SYNOPSIS

*void* **ssh_disconnect**(0: *int*);

**ssh_disconnect** takes one positional argument

## DESCRIPTION

This function takes the SSH session ID returned by **[ssh_connect(3)](ssh_connect.md)** and closes it. Passing 0 as session ID is explicitly allowed and does nothing. If there are any open channels, they are closed as well and their IDs will be marked as invalid.

The first unnamed parameter is the session ID as an *int*.

## RETURN

Nothing

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**