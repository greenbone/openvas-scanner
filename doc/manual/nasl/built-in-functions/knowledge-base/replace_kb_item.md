# replace_kb_item

## NAME

**replace_kb_item** - creates a new entry in the KB or replace the old value

## SYNOPSIS

*void* **replace_kb_item**(name: *string*, value: *any*);

**replace_kb_item** takes 2 named arguments.


## DESCRIPTION

This function is used to create new entries within the KB or replace existing ones. It is mainly used for inter-plugin communication, so data can be transferred between scripts. If this function is called multiple times with the same *name*, the old value is replaced.

The *name* parameter sets the name of the entry. It is used to retrieve the item again with [get_kb_item(3)](get_kb_item.md).

The *value* parameter sets the value of the entry. It can store any information provided and can be retrieved again with [get_kb_item(3)](get_kb_item.md). The type of the value can be either an integer or a string. If the value is of type integer, it is not possible to set it to -1.

## RETURN VALUE

None

## ERRORS

parameter *name* is missing

parameter *value* is missing

parameter *value* is *int* and its value is -1

## EXAMPLES

**1**: Create an entry
```cpp
replace_kb_item(name: "foo", value: "bar");
```

**2**: Create an entry and replace it
```cpp
replace_kb_item(name: "foo", value: "bar");
replace_kb_item(name: "foo", value: "baz");
```

## SEE ALSO

**[get_kb_item(3)](get_kb_item.md)**, **[get_kb_list(3)](get_kb_list.md)**, **[set_kb_item(3)](set_kb_item.md)**, **[get_host_kb_index(3)](get_host_kb_index.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
