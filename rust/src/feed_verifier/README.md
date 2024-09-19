# feed-verifier

Is a specialized cli program to verify if 

```
openvas -u
```

and 

```
scannerctl feed update
```

do have the same output within redis.

This is required to verify if the rust based scannerctl is downwards compatible to ospd-openvas.
