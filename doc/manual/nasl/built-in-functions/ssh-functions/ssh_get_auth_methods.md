# ssh_get_auth_methods

## NAME

**ssh_get_auth_methods** - get list of supported authentication schemes

## SYNOPSIS

*int* **ssh_get_auth_methods**(0: *int*);

**ssg_get_auth_methods** takes one positional argument

## DESCRIPTION

The first positional argument contains the SSH session ID as *int* returned by **[ssh_connect(3)](ssh_connect.md)**.

## RETURN VALUE

A comma separated list with enabled authentication methods or *NULL*.
The *NULL* value can have different reasons:
- The session ID is invalid
- No SSH user is set
- No authentication methods are enabled

## ERROR

Invalid session ID

Bad SSH session ID

## SEE ALSO

**[ssh_connect(3)](ssh_connect.md)**