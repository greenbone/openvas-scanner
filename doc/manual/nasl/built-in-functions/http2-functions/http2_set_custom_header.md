# http2_set_custom_header

## NAME

**http2_set_custom_header** - Set a custom header element in the header

## SYNOPSIS

*void* **http_set_custom_header**(handle: *int*, header_item: *string*);

**http_set_custom_header** takes two arguments.

## DESCRIPTION
Adds a new element to initialized handle header.

## RETURN VALUE
It returns an integer or NULL on error.

## EXAMPLES

**1** Set a new element in the header
```cpp
h = http2_handle();
display(h);
http2_set_custom_header(handle: h, handle_item: "Content-Type: application/json");
```

## SEE ALSO

**[http2_delete(3)](http2_delete.md)**, **[http2_get(3)](http2_get.md)**, **[http2_close_handle(3)](http2_close_handle.md)**, **[http2_head(3)](http2_head.md)**, **[http2_handle(3)](http2_handle.md)**, **[http2_post(3)](http2_post.md)**, **[http2_put(3)](http2_put.md)**, **[http2_get_response_code(3)](http2_get_response_code.md)**, **[http2_set_custom_header(3)](http2_set_custom_header.md)**
