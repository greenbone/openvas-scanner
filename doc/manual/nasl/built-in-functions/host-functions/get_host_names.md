# get_host_names

## NAME

**get_host_names** - get a list with found hostnames

## SYNOPSIS

*array* **get_host_names**();

**get_host_names** takes no arguments

## DESCRIPTION

Get a list of found hostnames or a IP of the current target in case no hostnames were found yet.

## RETURN VALUE

An *array* containing all found hostnames as *string*. The return type is always a NASL array.

## SEE ALSO

**[add_host_name(3)](add_host_name.md)**