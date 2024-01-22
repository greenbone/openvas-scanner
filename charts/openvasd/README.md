# Helm Chart for `openvasd` deployment 

## Requirements

This Helm chart is tested with k3s and Traefik. Note that other options may require unsupported changes.

## mTLS (Enabled by Default)

To use mTLS, store the server certificate and key as a secret named 'ingress-certificate', containing key.pem and certs.pem. For example, deploying `openvasd` into the 'openvasd' namespace with a generated certificate:

```bash
cd ../../rust/examples/tls/Self-Signed\ mTLS\ Method
sh server_certificates.sh
kubectl create secret generic ingress-certificate \
      --from-file=key.pem=./server.rsa \
      --from-file=certs.pem=./server.pem \
      --namespace openvasd

```

Additionally, populate client certificates within a 'client-certs' secret:

```bash
cd ../../rust/examples/tls/Self-Signed\ mTLS\ Method

kubectl create secret generic client-certs \
      --from-file=client1.pem=./client.pem \
      --namespace openvasd
```

There can be multiple client certificates.

Verify that the secrets are deployed:

```bash
kubectl describe secrets --namespace openvasd
```

## Install

To install `openvasd` Helm Chart from a local path, execute:

```bash
helm install openvasd ./openvasd/ -f openvasd/values.yaml --namespace openvasd --create-namespace openvasd
```

You can also override initial values within openvasd/values.yaml by providing an additional -f flag. For example:

```bash
helm install --namespace openvasd --create-namespace openvasd openvasd/ --values openvasd/values.yaml --values openvasd/http-root.yaml
```

This will start `openvasd` with http and with a API-KEY `changeme`.

## Preconfigured deployment scenarios

### mTLS

This is enabled by default. Please read the requirements sections.

### HTTP Single Instance

To deploy `openvasd` as an HTTP instance on the root path, execute:

```bash
helm install --namespace openvasd --create-namespace openvasd openvasd/ --values openvasd/values.yaml --values openvasd/http-root.yaml
```

## Accessing the service

When `routing.enabled` is enabled, you can access `openvasd` directly via either `http://localhost` (if you provide the the http-root.yaml values) or via `https://localhost`

For testing, you can use the following command:

```bash
curl --verbose --insecure --key $CLIENT_KEY --cert $CLIENT_CERT --request HEAD https://127.0.0.1
```

## Design decisions

### IngressRouteTCP instead of Ingress

To enable passthrough, IngressRouteTCP is used instead of the usual Ingress definition.

### OSPD and Redis via unix socket

OSPD is used in Unix socket mode to prevent users from bypassing `openvasd` and interfering with scans. 

The Redis instance is shared between OSPD and OpenVAS, started in Unix socket mode to ensure it is not used by another container.

### No scaling

Due to current architectural limitations, replica count and auto-scaling are disabled. OSPD lacks cluster capabilities and a database setup that allows sharing via multiple instances. Each replica would have its own state, requiring vertical scaling via deployment.
