# http_post

## NAME

**http_post** - formats an HTTP POST request for the server on the port.

## SYNOPSIS

*void* **http_post**(port: *int*, item: *string*, data: *string*);

**http_post** takes three named arguments.

## DESCRIPTION
Formats an HTTP POST request for the server on the port.
It will automatically handle the HTTP version and the basic or cookie based authentication. The arguments are port and item (the URL) and `data`.

## RETURN VALUE
It returns a string (the formatted request). Null on error

## EXAMPLES

**1** Get and display the formatted post request: 
```cpp
data = "some data";
req = http_post(port: 80, item: "http://localhost/index.html", data: data);
display (req);
```

## SEE ALSO

**[cgibin(3)](cgibin.md)**, **[http_delete(3)](http.md)**, **[http_get(3)](http.md)**, **[http_close_socket(3)](http.md)**, **[http_head(3)](http.md)**, **[http_open_socket(3)](http.md)**, **[http_post(3)](http.md)**, **[http_put(3)](http.md)**
