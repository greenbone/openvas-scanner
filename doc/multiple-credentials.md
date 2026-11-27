# Multiple credentials per service

A scan target can carry several credentials for the same service (SSH, SMB,
SNMP, KRB5, ESXi). Each credential may be restricted to a list of hosts.
When a host is scanned, the credential matching that host is selected and
published as the scan preferences read by the NASL scripts.

Credentials are part of the target in the scan JSON. The optional `hosts`
field ties a credential to specific hosts.

```json
"credentials": [
  { "service": "ssh", "port": 22,
    "up": { "username": "default", "password": "pass" } },
  { "service": "ssh", "port": 2222,
    "hosts": ["192.168.1.0/24", "web.example.com"],
    "usk": { "username": "admin", "password": "passphrase",
             "private": "<base64 key>" } },
  { "service": "smb", "hosts": ["10.0.0.1-10"],
    "up": { "username": "user", "password": "pass" } }
]
```

**openvasd** handles scan preferences. The first credential without
`hosts` field (missing or empty) of each service is written as the regular default
preferences (the samepreferences used before this feature). Credentials with
`hosts` and later credentials without `hosts` are not written as defaults.
The complete credential list is serialized into one scan preference,
`multi-credentials`, as a JSON string.
**openvas** gets the scan preferences and process them. If `multi-credentials` is set,
parses it and stores the credential list in `globals->credentials`.
Later, when a new host process is started and before any plugin
runs, a function for credential overriding is called. Then, for each
credential service, iterates over the list of host in a credential and 
the first credential whose `hosts` list contains the current scanned host is stored
and will be used for the rest of host scan.
This only affects the forked per host process, so other hosts are unaffected.
If nothing matches, the default credential stays in place.

Summarizing, this are the important rules:
- Matching is , in the order given in the JSON.
- A credential without `hosts` never matches in C; it can only be the default,
  the first one without hosts, per service, set in **openvasd**.
- Each service is selected independently. E.g. an SSH match doesn't influence SMB.
- A matching credential replaces all values of that service. Missing
  optional values are set to an empty NULL, so nothing leaks from the
  default credential.
