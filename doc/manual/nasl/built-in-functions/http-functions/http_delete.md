# http_delete

## NAME

**http_delete** - formats an HTTP DELETE request for the server on the port.

## SYNOPSIS

*void* **http_delete**(port: *int*, item: *string*, data: *string*);

**http_delete** takes three named arguments.

## DESCRIPTION
Formats an HTTP DELETE request for the server on the port.
It will automatically handle the HTTP version and the basic or cookie based authentication. The arguments are port and item (the URL). `data` argument is not compulsory and probably useless in this function.

## RETURN VALUE
It returns a string (the formatted request). Null on error

## EXAMPLES

**1** Get and display the delete request: 
```cpp
url = "http://localhost/";
file = url + "puttest" + rand() + ".html";
req = http_delete(port: 80, item: file);
display (req);
```

## SEE ALSO

**[cgibin(3)](cgibin.md)**, **[http_delete(3)](http.md)**, **[http_get(3)](http.md)**, **[http_close_socket(3)](http.md)**, **[http_head(3)](http.md)**, **[http_open_socket(3)](http.md)**, **[http_post(3)](http.md)**, **[http_put(3)](http.md)**
