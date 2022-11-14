# set_kb_item

## NAME

**set_kb_item** - creates a new entry in the KB

## SYNOPSIS

*void* **set_kb_item**(name: *string*, value: *any*);

*void* **set_kb_item**(name: *string*, value: *any*, expire: *int*);

**set_kb_item** takes either 2 or 3 named arguments.


## DESCRIPTION

This function is used to create new entries within the KB. It is mainly used for inter-plugin communication, so data can be transferred between scripts. If this function is called multiple times with the same *name*, a list is created.

The *name* parameter sets the name of the entry. It is used to retrieve the item again with get_kb_item().

The *value* parameter sets the value of the entry. It can store any information provided and can be retrieved again with get_kb_item(). The type of the value can be either an integer or a string.

The *expire* parameter is used for volatile entries. It is optional and determines when the entry expires in seconds. This value is only relevant, when the options *maxmemory* and *maxmemory-policy* are set in the *redis.conf* entries with an expire set will be evicted when *maxmemory* is reached. This way memory issues can be prevent.


## RETURN VALUE

None

## ERRORS

parameter *name* is missing

parameter *value* is missing

parameter *value* is *int* and its value is -1

parameter *expire* is -1

## EXAMPLES

**1**: Create an entry, which expires after 10 minutes
```cpp
set_kb_item(name: "foo", value: "bar", expire: 600);
```

**2**: Create an entry, which does not expire
```cpp
set_kb_item(name: "age", value: "42");
```


**3**: Create a list
```cpp
set_kb_item(name: "hosts", value: "foo");
set_kb_item(name: "hosts", value: "bar");
```

## NOTES

**When to use expire:** Should be used as often as possible. Should
be used for the webpage caching functions. Should be used for
keys which are not 100% necessary and which can be deleted if we
run into memory limits. Should be used for large keys. Should be
used for keys which are only needed for a short amount of time.

## SEE ALSO

**[get_kb_item(3)](get_kb_item.md)**, **[get_kb_list(3)](get_kb_list.md)**, **[replace_kb_item(3)](replace_kb_item.md)**, **[get_host_kb_index(3)](get_host_kb_index.md)**, **[openvas-nasl(1)](../../openvas-nasl.md)**
