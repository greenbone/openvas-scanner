# get_host_kb_index

## NAME

**get_host_kb_index** - Get the KB index of the host running the current script

## SYNOPSIS

*int* **get_host_kb_index**(name: *string*, value: *any*);

**get_host_kb_index** takes no arguments


## DESCRIPTION

This function will return the index number of the currently used Redis Database. This index belongs to the host, which is currently scanned.


## RETURN VALUE

KB index, *int* or None, when redis index cannot be determined


## SEE ALSO

**[get_kb_item(3)](get_kb_item.md)**, **[get_kb_list(3)](get_kb_list.md)**, **[replace_kb_item(3)](replace_kb_item.md)**, **[set_kb_item(3)](set_kb_item.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
