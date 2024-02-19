# How do I resume a scan?

Although `openvasd` just has the `start` and `stop` actions, you can resume a stopped task by creating a new scan and providing finished hosts within `exclude_hosts`.

To do that, you start a scan, collect all results with the type `host_end`, and then stop the scan. Next, you create a new scan with the `ip_address` of the already finished scans in `exclude_hosts`.

As an example, we create a scan to scan the hosts `127.0.0.1`, `localhost` with the following `scan.json`:

```
{
  "target": {
    "hosts": [
      "127.0.0.1",
      "localhost"
    ],
    "ports": [
      {
        "protocol": "tcp",
        "range": [
          {
            "start": 22,
            "end": 22
          }
        ]
      }
    ],
    "credentials": [
      {
        "service": "ssh",
        "port": 22,
        "up": {
          "username": "noname",
          "password": "nopass"
        }
      }
    ]
  },
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.90022"
    }
  ]
}
```

we create the scan and start it:

```
curl -k --cert $CERT --key $KEY "https://localhost/scans" -d @scan.json
curl -k --cert $CERT --key $KEY "https://localhost/scans/$ID" -d "{ \"action\": \"start\"}"
curl -k --cert $CERT --key $KEY "https://localhost/scans/$ID" 
```

The results contain something like:
```
...
  {
    "id": 2,
    "type": "host_end",
    "ip_address": "127.0.0.1",
    "oid": "",
    "message": "Mon Feb 19 13:54:07 2024"
  }
...
```
The type `host_end` indicates that a host was scanned.


Then we stop it:
```
curl -k --cert $CERT --key $KEY "https://localhost/scans/$ID" -d "{ \"action\": \"stop\"}"
```

We assume that when we stopped it, it just scanned `127.0.0.1`, so we create a scan with it excluded in hosts:

```
{
  "target": {
    "hosts": [
      "localhost"
    ],
    "excluded_hosts": [
      "127.0.0.1"
    ],
    "ports": [
      {
        "protocol": "tcp",
        "range": [
          {
            "start": 22,
            "end": 22
          }
        ]
      }
    ],
    "credentials": [
      {
        "service": "ssh",
        "port": 22,
        "up": {
          "username": "noname",
          "password": "nopass"
        }
      }
    ]
  },
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.90022"
    }
  ]
}
```

when creating the new scan and starting it, it should not scan `127.0.0.1` again.

```
curl -k --cert $CERT --key $KEY "https://localhost/scans" -d @scan.json
curl -k --cert $CERT --key $KEY "https://localhost/scans/$ID" -d "{ \"action\": \"start\"}"
curl -k --cert $CERT --key $KEY "https://localhost/scans/$ID" 
```

This is mainly useful when you scan ip ranges.
