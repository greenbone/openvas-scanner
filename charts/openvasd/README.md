Contains the helm chart to deploy openvasd.

# Install

To install openvasd helm chart from a local path execute

```
helm install openvasd ./openvasd/ -f openvasd/values.yaml --namespace openvasd --create-namespace openvasd
```

You can also provide override the initial values within `openvasd/values.yaml` by providing an additional `-f` flag.

As an example imagine you want to override the openvas image to your forked one you can create `~/openvasd.yaml` file containing:

```
# Contains openvasd
openvas:
  repository: example/openvas-scanner
  pullPolicy: Always
  tag: "edge"
```

if you then execute:
```
helm install openvasd ./openvasd/ -f openvasd/values.yaml -f ~/openvasd.yaml
```

it will use `nichtsfrei/openvas-scanner` instead of `greenbone/openvas-scanner`.

# Preconfigured deployment scenarios

## http single instance

To deploy openvasd as http intance on the root path execute:
```
helm install --namespace openvasd --create-namespace openvasd openvasd/ --values openvasd/values.yaml --values openvasd/http-root.yaml
```
## TLS configuration

This chart is provided with server certificate and private key for example purposes and they should not be used in production systems. Certificate and key where created with [this scripts](../../rust/examples/tls/Self-Signed mTLS Method)

If you want to use your own key/cert pair, you have to base64 encode them and replace the ones in [server-private-key.yaml](templates/server-private-key.yaml).

If you want to enable Self-signed mTLS for client authentication replace the certificate in [client-cets.yaml](templates/client-certs). You can add as many certificates as you have authenticated clients.

For encoding the certificates use the following command
```
echo -n "$(cat certs.pem)" | base64
echo -n "$(cat key.pem)" | base64
```

You can verify that the secrets where mounted with the following command:

`kubectl describe secrets --namespace openvasd`


## Accessing the service

Once you installed the containers, run the following commands to rollout the pods and forward the por to access the service

`kubectl rollout status --watch --timeout 600s deployment/openvasd`

Get the pod name
`export POD_NAME=$(kubectl get pods --namespace openvasd -l "app.kubernetes.io/name=openvasd,app.kubernetes.io/instance=openvasd" -o jsonpath="{.items[0].metadata.name}")`

Forward the port
`kubectl --namespace openvasd port-forward $POD_NAME 8443:443`

For testing, you can use the following command:

`curl --verbose --key $CLIENT_KEY --cert $CLIENT_CERT --insecure --request HEAD https://127.0.0.1:8443 -H "X-API-KEY: changeme"`


# Design decisions

## OSPD and Redis via unix socket

Although it is possible to start OSPD with TLS, it is used in unix socket mode to prevent a user to bypass openvasd and interfere with those scans.

Unfortunately the redis instance is shared between ospd and openvas without any clear separation. It is crucial that the redis instance used by them cannot be modified elsewhere.
To ensure redis is not used by another container, it is also started in unix socket mode.

## No scaling

Due to the current architectural limitation replica count and auto-scaling is completely disabled.

The reason for that is that openvasd requires ospd which has no cluster capabilities nor a database setup that allows sharing via multiple instances.

That means that each replica would have a completely own state and reqires vertical scaling via deployment so that a customer can choose which openvasd to use.
