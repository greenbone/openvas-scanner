// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

mod advisories;
mod credential;
mod host_info;
mod parameter;
mod port;
mod result;
mod scan;
mod scan_action;
mod scanner_preference;
mod status;
mod target;
mod vt;

pub use advisories::*;
pub use credential::*;
pub use host_info::*;
pub use parameter::*;
pub use port::*;
pub use result::*;
pub use scan::*;
pub use scan_action::*;
pub use scanner_preference::*;
pub use status::*;
pub use target::*;
pub use vt::*;

use serde::Serializer;

fn censor<S, T>(_: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str("***")
}

#[cfg(test)]
//#[cfg(feature = "serde_support")]
mod tests {

    use super::scan::Scan;

    #[test]
    fn parse_minimal() {
        let json_str = r#"{
    "target": {
        "hosts": [
        "127.0.0.1"
        ],
        "ports": [
        {
            "range": [{"start": 22}]
        }
        ]
    },
    "vts": [
        {
        "oid": "1.3.6.1.4.1.25623.1.0.10267"
        }
    ]
}
"#;
        // tests that it doesn't panic when parsing the json
        let _: Scan = serde_json::from_str(json_str).unwrap();
    }

    #[test]
    fn parses_complex_example() {
        let json_str = r#"{
  "target": {
    "hosts": [
      "127.0.0.1",
      "192.168.0.1-15",
      "10.0.5.0/24",
      "::1",
      "2001:db8:0000:0000:0000:0000:0000:0001-00ff",
      "2002::1234:abcd:ffff:c0a8:101/64",
      "examplehost"
    ],
    "ports": [
      {
        "protocol": "udp",
        "range": [{"start": 22}, {"start": 1024, "end": 1030}]
      },
      {
        "protocol": "tcp",
        "range": [{"start": 24, "end": 30}]
      },
      {
        "range": [{"start": 100, "end": 1000}]
      }
    ],
    "credentials": [
      {
        "service": "ssh",
        "port": 22,
        "usk": {
          "username": "user",
          "password": "pw",
          "private": "ssh-key..."
        }
      },
      {
        "service": "smb",
        "up": {
          "username": "user",
          "password": "pw"
        }
      },
      {
        "service": "snmp",
        "snmp": {
          "username": "user",
          "password": "pw",
          "community": "my_community",
          "auth_algorithm": "md5",
          "privacy_password": "priv_pw",
          "privacy_algorithm": "aes"
        }
      }
    ],
    "alive_test_ports": [
      {
        "protocol": "tcp",
        "range": [{"start": 1, "end": 100}]
      },
      {
        "range": [{ "start": 443 }]
      }
    ],
    "alive_test_methods": [
      "icmp",
      "tcp_syn",
      "tcp_ack",
      "arp",
      "consider_alive"
    ],
    "reverse_lookup_unify": true,
    "reverse_lookup_only": false
  },
  "scanner_preferences": [
    {
      "id": "target_port",
      "value": "443"
    },
    {
      "id": "use_https",
      "value": "1"
    },
    {
      "id": "profile",
      "value": "fast_scan"
    }
  ],
  "vts": [
    {
      "oid": "1.3.6.1.4.1.25623.1.0.10662",
      "parameters": [
        {
          "id": 1,
          "value": "200"
        },
        {
          "id": 2,
          "value": "yes"
        }
      ]
    },
    {
      "oid": "1.3.6.1.4.1.25623.1.0.10330"
    }
  ]
}
"#;
        // tests that it doesn't panic when parsing the json
        let s: Scan = serde_json::from_str(json_str).unwrap();

        let _b = bincode::encode_to_vec(s, bincode::config::standard()).unwrap();
        //let _: Target = bincode::deserialize(&b).unwrap();
    }
}
