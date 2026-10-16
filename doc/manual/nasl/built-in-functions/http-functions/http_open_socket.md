# http_open_socket(3nasl)

## NAME

**http_open_socket** - opens a socket.

## SYNOPSIS

*void* **http_open_socket**(*int*);

**http_open_socket** takes one unnamed argument

## DESCRIPTION
Opens a socket to the given port. It sets a 64K buffer for IO.

## RETURN VALUE
An integer value, the socket

## EXAMPLES

**1** Open and close a socket. Use the socket to send a get request: 
```cpp
soc = http_open_socket (port: 80);

url = "http://localhost/";
file = url + "index.html";
req = http_get(port: 80, item: file);

send(socket: soc, data: req);
r = http_recv_headers2(socket:soc);
display (r);

http_close_socket(soc);
```

## SEE ALSO

**[cgibin(3nasl)](cgibin.md)**, **[http_delete(3nasl)](http_delete.md)**, **[http_get(3nasl)](http_get.md)**, **[http_close_socket(3nasl)](http_close_socket.md)**, **[http_head(3nasl)](http_head.md)**, **[http_open_socket(3nasl)](http_open_socket.md)**, **[http_post(3nasl)](http_post.md)**, **[http_put(3nasl)](http_put.md)**
