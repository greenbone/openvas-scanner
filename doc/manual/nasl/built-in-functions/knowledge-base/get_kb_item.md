# get_kb_item

## NAME

**get_kb_item** - retrieves an entry from the KB

## SYNOPSIS

*any* **get_kb_item**(0: *string*);

**get_kb_item** takes 1 positional argument.


## DESCRIPTION

This function is used to retrieve entries from the KB. It is mainly used for inter-plugin communication, so data can be transferred between scripts.

If the item is a list, the plugin will fork and each child process will use a different value. The openvas-scanner does NOT remember which child got which value: reading the same item a second time will fork again! You should not call this function when some connections are open if you do not want to see several processes fighting to read or write on the same socket. Although it is internally based on forking, execution of a script is NOT parallel.

The first positional argument determines the name of the entry, which should be retrieved.


## RETURN VALUE

KB item, either *int* or *string* or None, when key does not exist

## EXAMPLES

**1**: Create an entry, and get it
```cpp
set_kb_item(name: "foo", value: "bar");
display(get_kb_item("foo"));
# should print bar
```

**2**: Create multiple entries and get them by forking
```cpp
set_kb_item(name: "hosts", value: "foo");
set_kb_item(name: "hosts", value: "bar");
display(get_kb_item("hosts"));
# should print two lines, one with foo and one with bar
```


## NOTES

To avoid forking use [get_kb_list(3)](get_kb_list.md) instead

## SEE ALSO

**[set_kb_item(3)](set_kb_item.md)**, **[get_kb_list(3)](get_kb_list.md)**, **[replace_kb_item(3)](replace_kb_item.md)**, **[get_host_kb_index(3)](get_host_kb_index.md)**, **[display(3)](../misc/display)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
