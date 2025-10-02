Generates self signed client and server certificates that can be used for testing

To generate a
- server.rsa
- server.pem
- client.rsa
- client.pem
call

```
make
```

To generate a new certificates regardless if they are available or not call:

```
make -B
```

To remove the certificates call:

```
make remove
```
