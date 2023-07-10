Contains the helm chart to deploy openvasd.

# Install

To install openvasd helm chart from a local path execute

``` 
helm install openvasd ./openvasd/ -f openvasd/values.yaml
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

# Design decisions

## OSPD and Redis via unix socket

Although it is possible to start OSPD with TLS, it is used in unix socket mode to prevent a user to bypass openvasd and interfere with those scans.

Unfortunately the redis instance is shared between ospd and openvas without any clear separation. It is crucial that the redis instance used by them cannot be modified elsewhere. 

To ensure that redis is also started in unix socket mode.

## No scaling

Due to the current architectural limitation replica count and auto-scaling is completely disabled. 

The reason for that is that openvasd requires ospd which has no cluster capabilities nor a database setup that allows sharing via multiple instances. 

That means that each replica would have a completely own state and reqires vertical scaling via deployment so that a customer can choose which openvasd to use.
