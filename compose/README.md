# OpenVASD compose definition

This dir contains the compose definition for:
- docker-compose
- podman-compose

Requirements:
- either podman-compose or docker-compose
- Optional (for tests): openssl, make, curl, jq

It is divided into three definitions:
1. base.yaml - contains the actual definition of the services starts OpenVASD in http mode
2. tls.yaml - overrides the settings within base.yaml to start OpenVASD in TLS mode
3. mtls.yaml - overrides the settings within base.yaml to start OpenVASD in mTLS mode (preferred)

Which means to start openvasd with http:

```
podman-compose -f base.yaml
```

in TLS mode

```
podman-compose -f base.yaml -f tls.yaml
```

in mTLS mode:

```
podman-compose -f base.yaml -f mtls.yaml
```

when in mTLS mode you have to provide the client-certificate and the corresponding key when connecting to OpenVASD:

```
curl -vk \
    --key client-keys/client1.key \
    --cert client-certs/client1.pem \
    https://localhost:3000/scans
```

On default the compose definitions (tls.yaml as well as mtls.yaml) use the certificates:
- ./openvasd-server.key
- ./openvasd-server.pem
the directory
- ./client-certs
for the client certificates.

You can either copy your certificates into that location or set the environment variables:
- OPENVASD_SERVER_KEY - the key file of your certificate
- OPENVASD_SERVER_PEM - the pem file of your certificate
- OPENVASD_CLIENT_KEYS - the directory containing public certificates of clients that are allowed to use OpenVASD 

If you don't have certificates, but want to test OpenVASD you can call:

```
make
```

Additionally to the OpenVASD compose definition we also provide a possibility to verify the setup.

This is done by adding `test/victim.yaml` to the compose chain like

```
podman-compose -f base.yaml -f mtls.yaml -f tests/victim.yaml
```

and then use `make` within the `tests` directory to create and start predefined scans:

```bash
make create-victim-simple-auth-ssh
make start-victim-simple-auth-ssh
make results-victim-simple-auth-ssh
make status-victim-simple-auth-ssh
```

The naming scheme of that Makefile is `command-` and the name of the json
within `tests/scans` without the json suffix.

Depending on your auto-completion behaviour the `create-` should be able to
expand immediately while 
- `start-`, 
- `results-`, 
- `status-`, 
- `stop-` 
- `rm-` 
are only available for scans that have already been created.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| OPENVASD_EXTERNAL_BIND_ADDRESS |127.0.0.1:3000 |The bind address on the host. |
| OPENVAS_LOG_LEVEL | 64 | The numeric log level definition used for openvas. See base.yaml comment on `configure-openvas-log` for more details|
| OPENVAS_REDIS_MEMORY_LIMIT | 0 | Prevents the host to allocate more memory for redis. |
| OPENVAS_REDIS_MEMORY_RESERVATION | 0 | Host hint to have at least that amount of memory available for redis. |
| OPENVAS_REDIS_RESTART_CONDITION | on-failure | Dictates when the container manager should restart the container when it is not running anymore|
| OPENVASD_MEMORY_LIMIT | 0 | Prevents the host to allocate more memory for OpenVASD. |
| OPENVASD_MEMORY_RESERVATION | 0 | Host hint to have at least that amount of memory available for OpenVASD. |
| OPENVASD_RESTART_CONDITION | on-failure | Dictates when the container manager should restart the container when it is not running anymore|

