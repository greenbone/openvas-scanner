# http_head

## NAME

**http_head** - formats an HTTP HEAD request for the server on the port.

## SYNOPSIS

*void* **http_head**(port: *int*, item: *string*, data: *string*);

**http_head** takes three named arguments.

## DESCRIPTION
Formats an HTTP HEAD request for the server on the port.
It will automatically handle the HTTP version and the basic or cookie based authentication. The arguments are port and item (the URL). `data` argument is not compulsory and probably useless in this function.

## RETURN VALUE
It returns a string (the formatted request). Null on error

## EXAMPLES

**1** Get and display the head request: 
```cpp
req = http_head(port: 80, item: "/~root");
display (req);
```

## SEE ALSO

**[cgibin(3)](cgibin.md)**, **[http_delete(3)](http.md)**, **[http_get(3)](http.md)**, **[http_close_socket(3)](http.md)**, **[http_head(3)](http.md)**, **[http_open_socket(3)](http.md)**, **[http_post(3)](http.md)**, **[http_put(3)](http.md)**
