# http_close_socket

## NAME

**http_close_socket** - closes a socket.

## SYNOPSIS

*void* **http_close_socket**(*int*);

**http_close_socket** takes one unnamed argument

## DESCRIPTION
It is identical to close but this may change in the future. 

## RETURN VALUE


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

**[cgibin(3)](cgibin.md)**, **[http_delete(3)](http_delete.md)**, **[http_get(3)](http_get.md)**, **[http_close_socket(3)](http_close_socket.md)**, **[http_head(3)](http_head.md)**, **[http_open_socket(3)](http_open_socket.md)**, **[http_post(3)](http_post.md)**, **[http_put(3)](http_put.md)**
