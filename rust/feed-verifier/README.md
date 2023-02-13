# feed-verifier

Is a specialized cli program to verify if 

```
openvas -u
```

and 

```
nasl-cli feed update
```

do have the same output within redis.

This is required to verify if the rust based nasl-cli is downwards compatible to ospd-openvas.
