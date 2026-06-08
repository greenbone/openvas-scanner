# cgibin

## NAME

**cgibin** - Get the cgi-bin path elements.

## SYNOPSIS

*void* **cgibin**();

**cgibin** takes no argument.

## DESCRIPTION
Returns the cgi-bin path elements. In fact the NASL interpreter forks and each process gets one value.

## RETURN VALUE
String containing the path.

## EXAMPLES

**1** Get and display the path: 
```cpp
path = cgibin();
display (path);
```

## SEE ALSO

**[cgibin(3)](cgibin.md)**, **[http_delete(3)](http_delete.md)**, **[http_get(3)](http_get.md)**, **[http_close_socket(3)](http_close_socket.md)**, **[http_head(3)](http_head.md)**, **[http_open_socket(3)](http_open_socket.md)**, **[http_post(3)](http_post.md)**, **[http_put(3)](http_put.md)**
