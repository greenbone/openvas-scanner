# local registry 

Contains a Makefile to start a local docker registry v2 on port 5000 as well as an authentication service for bearer token on port 5001.

Depends on:
- openssl,
- docker

To push images into the local registry you need to login and then retag a image to `localhost:5000/myname/myimage:mytag`:

```
make
docker login localhost:5000
docker tag nichtsfrei/victim:latest localhost:5000/nichtsfrei/victim:latest
docker push localhost:5000/nichtsfrei/victim:latest
```

The auth server accepts any username and password combination.

This allows us to verify a scan without requiring an external service.

## Example json

```json
{
  "target": {
    "hosts": [
      "oci://localhost:5000/nichtsfrei/victim"
    ],
   "credentials": [
      {
        "service": "generic",
        "up": {
          "username": "holla",
          "password": "diewaldfee"
        }
      }
    ]
  },
  "scan_preferences": [
    {
      "id": "accept_invalid_certs",
      "value": "true"
    }
  ]
}
```

To scan the previously added image.
