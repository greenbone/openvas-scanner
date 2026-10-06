# http2_handle(3nasl)

## NAME

**http2_handle** - Creates a handle for http requests.

## SYNOPSIS

*void* **http_handle**(ca_cert: *string*);

**http_handle** takes one optional named argument.

## DESCRIPTION
Initialize a handle for performing http requests. It optionally receives a CA certificate in PEM format for performing peer verification.

## RETURN VALUE
It returns an integer or NULL on error.

## EXAMPLES

**1** Get the handle identifier
```cpp
h = http2_handle();
display(h);
```

## SEE ALSO

**[http2_delete(3nasl)](http2_delete.md)**, **[http2_get(3nasl)](http2_get.md)**, **[http2_close_handle(3nasl)](http2_close_handle.md)**, **[http2_head(3nasl)](http2_head.md)**, **[http2_handle(3nasl)](http2_handle.md)**, **[http2_post(3nasl)](http2_post.md)**, **[http2_put(3nasl)](http2_put.md)**, **[http2_get_response_code(3nasl)](http2_get_response_code.md)**, **[http2_set_custom_header(3nasl)](http2_set_custom_header.md)**
