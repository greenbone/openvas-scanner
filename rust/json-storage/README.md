# json-storage

Is a storage implementation that transforms NVTs to json.

It supports single json transformation as well as array.

To use it you need to create a writer instance of your choice in the examples we will use a vector.

## NVT

Transforms a NVT to the json structure:
```text
{
  "oid": "116.101.115.116",
  "name": "zeroone",
  "filename": "zeroone.nasl",
  "tag": {
    "solution": "Solution",
    "solution_method": "SolutionMethod",
    "last_modification": 1348380934,
    "solution_type": "Mitigation",
    "creation_date": 1348380934,
    "severity_origin": "SeverityOrigin",
    "qod_type": "exploit",
    "impact": "Impact",
    "insight": "Insight",
    "qod": 30,
    "severity_date": 1348380934,
    "summary": "Summary",
    "vuldetect": "Vuldetect",
    "affected": "Affected",
    "deprecated": true,
    "severity_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N",
    "cvss_base_vector": "AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N"
  },
  "dependencies": [
    "zero.nasl"
  ],
  "required_keys": [
    "hostname/test"
  ],
  "mandatory_keys": [
    "hostname/te"
  ],
  "excluded_keys": [
    "hostname/prod"
  ],
  "required_ports": [
    "22"
  ],
  "required_udp_ports": [
    "21"
  ],
  "references": [
    {
      "class": "URL",
      "id": "unix:///var/lib/really.sock"
    }
  ],
  "preferences": [
    {
      "id": 0,
      "class": "check_box",
      "name": "0",
      "default": "0"
    }
  ],
  "category": "destructive_attack",
  "family": "family"
}
```

### Element

To create a single json element per dispatch you can use the ItemDispatcher with a writer of your choice:

```
let mut buf = Vec::with_capacity(1208);
let dispatcher = json_storage::ItemDispatcher::as_dispatcher::<String>(&mut buf);
```

### Array

To create an array for elements per dispatch call:

```
let mut buf = Vec::with_capacity(1208);
let mut ja = json_storage::ArrayWrapper::new(&mut buf);
let dispatcher = json_storage::ItemDispatcher::as_dispatcher::<String>(&mut ja);
// do your work
ja.end();
```

This will convert each dispatched NVT to an json element in an array:

```test
[
  {
    "oid": "48",
    ...
  },
  {
    "oid": "49",
    ...
  },
  {
    "oid": "49.48",
    ...
  }
]
```
