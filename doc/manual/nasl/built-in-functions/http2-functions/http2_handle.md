# http2_handle

## NAME

**http2_handle** - Creates a handle for http requests.

## SYNOPSIS

*void* **http_handle**();

**http_handle** takes no argument.

## DESCRIPTION
Initialize a handle for performing http requests.

## RETURN VALUE
It returns an integer or NULL on error.

## EXAMPLES

**1** Get the handle identifier
```cpp
h = http2_handle();
display(h);
```

## SEE ALSO

**[http2_delete(3)](http2_delete.md)**, **[http2_get(3)](http2_get.md)**, **[http2_close_handle(3)](http2_close_handle.md)**, **[http2_head(3)](http2_head.md)**, **[http2_handle(3)](http2_handle.md)**, **[http2_post(3)](http2_post.md)**, **[http2_put(3)](http2_put.md)**, **[http2_get_response_code(3)](http2_get_response_code.md)**, **[http2_set_custom_header(3)](http2_set_custom_header.md)**
