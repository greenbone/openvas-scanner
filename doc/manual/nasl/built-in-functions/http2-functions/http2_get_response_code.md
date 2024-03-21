# http2_get_response_code

## NAME

**http2_get_response_code** - Gets the response code

## SYNOPSIS

*void* **http2_get_response_code**(handle: *int*);

**http_get** takes one argument.

## DESCRIPTION
After performing a request, is possible to get the response code calling this function and giving the handle identifier.

## RETURN VALUE
It returns an intenger with the response code. Null on error

## EXAMPLES

**1** Get and display the response code:
```cpp
h = http2_handle();
display(h);

r = http2_get(handle:h, port:3000, item:"/vts", schema:"http");
display("response: ", r);
rc = http2_get_response_code(handle:h);
display("return code: ", rc);
```

## SEE ALSO

**[http2_delete(3)](http2_delete.md)**, **[http2_get(3)](http2_get.md)**, **[http2_close_handle(3)](http2_close_handle.md)**, **[http2_head(3)](http2_head.md)**, **[http2_handle(3)](http2_handle.md)**, **[http2_post(3)](http2_post.md)**, **[http2_put(3)](http2_put.md)**, **[http2_get_response_code(3)](http2_get_response_code.md)**, **[http2_set_custom_header(3)](http2_set_custom_header.md)**
