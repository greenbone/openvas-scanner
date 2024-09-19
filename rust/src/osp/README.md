# OSP

OSP is a Rust crate designed for sending commands to an OSPD socket. It enables
 the execution of the following commands:

- Start: to initiate a scan
- Delete: to delete a specific scan
- Stop: to terminate a running scan
- Get: to retrieve scan results
- GetDelete: to fetch and delete scan results simultaneously

For example, here is how you can use OSP:

```rust,ignore
let json_str = r#"{
  "target": {
    "hosts": [
      "127.0.0.1"
    ]
  },
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.10330"
    }
  ]
}"#;

// Deserialize json into a `Scan` struct
let scan: osp::Scan = serde_json::from_str(json_str).unwrap();

// Create a `Start` command using the `Scan`
let cmd = osp::ScanCommand::Start(scan);

// Send the command to the OSPD socket
println!("{:?}", osp::send_command("/run/ospd/ospd-openvas.sock", cmd))
```
