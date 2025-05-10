# http2_delete

## NAME

**http2_delete** - performs an HTTP2 DELETE request for the server on the port.

## SYNOPSIS

*void* **http_delete**(handle: *int*, port: *int*, schema: *string*, item: *string*, data: *string*);

**http_delete** takes five named arguments.

## DESCRIPTION
Performs an HTTP2 DELETE request for the server on the port. It tries to force the version HTTP2 if `https` (default) is passed as schema uses ALPN to negotiate the protocol to use.

If `http` is passed as schema, the function includes an upgrade header in the initial request to the host to allow upgrading to HTTP/2.
The arguments are port and item (the path, query, etc), schema (optional, default `https`) and `data` (optional).

## RETURN VALUE
It returns a string (the http response). Null on error

## EXAMPLES

**1** Delete and display the formatted delete request:
```cpp
h = http2_handle();
display(h);

r = http2_delete(handle:h, port:3000, item:"/vts", schema:"http");
display("response: ", r);
rc = http2_get_response_code(handle:h);
display("return code: ", rc);
```

## SEE ALSO

**[http2_delete(3)](http2_delete.md)**, **[http2_get(3)](http2_get.md)**, **[http2_close_handle(3)](http2_close_handle.md)**, **[http2_head(3)](http2_head.md)**, **[http2_handle(3)](http2_handle.md)**, **[http2_post(3)](http2_post.md)**, **[http2_put(3)](http2_put.md)**, **[http2_get_response_code(3)](http2_get_response_code.md)**, **[http2_set_custom_header(3)](http2_set_custom_header.md)**
