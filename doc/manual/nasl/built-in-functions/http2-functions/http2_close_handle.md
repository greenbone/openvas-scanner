# http2_close_handle(3nasl)

## NAME

**http2_close_handle** - Close a handle for http requests previously initialized.

## SYNOPSIS

*void* **http_close_handle**(handle: *int*);

**http_close_handle** takes one argument.

## DESCRIPTION
 Close a handle for http requests previously initialized.

## RETURN VALUE
It returns an integer or NULL on error.

## EXAMPLES

**1** Close the handle identifier
```cpp
h = http2_handle();
display(h);
http2_close_handle(h);
```

## SEE ALSO

**[http2_delete(3nasl)](http2_delete.md)**, **[http2_get(3nasl)](http2_get.md)**, **[http2_close_handle(3nasl)](http2_close_handle.md)**, **[http2_head(3nasl)](http2_head.md)**, **[http2_handle(3nasl)](http2_handle.md)**, **[http2_post(3nasl)](http2_post.md)**, **[http2_put(3nasl)](http2_put.md)**, **[http2_get_response_code(3nasl)](http2_get_response_code.md)**, **[http2_set_custom_header(3nasl)](http2_set_custom_header.md)**
