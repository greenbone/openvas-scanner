// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::nasl::syntax::{LoadError, Loader};

#[derive(Default)]
pub struct NoOpLoader {}

/// Is a no operation loader for test purposes.
impl Loader for NoOpLoader {
    fn load(&self, _: &str) -> Result<String, LoadError> {
        Ok(String::default())
    }

    fn root_path(&self) -> Result<std::string::String, crate::nasl::syntax::LoadError> {
        Ok(String::default())
    }
}

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::nasl::builtin::ContextFactory;
use crate::nasl::test_prelude::*;
use crate::storage::item::{NvtPreference, NvtRef, PreferenceType::*, TagKey, ACT::Denial};
use crate::storage::{item, ContextKey, DefaultDispatcher, Retrieve, Retriever};

#[test]
fn description() {
    let code = r#"
rc = 23;
if(description)
{
    script_oid("0.0.0.0.0.0.0.0.0.1");
    script_version("2022-11-14T13:47:12+0000");
    script_tag(name:"creation_date", value:"2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)");
    script_name("that is a very long and descriptive name");
    script_category(ACT_DENIAL);
    script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
    script_family("Denial of Service");
    script_dependencies("ssh_detect.nasl", "ssh2.nasl");
    script_require_ports("Services/ssh", 22);
    script_mandatory_keys("ssh/blubb/detected");
    script_xref(name:"URL", value:"http://freshmeat.sourceforge.net/projects/eventh/");
    script_exclude_keys("Settings/disable_cgi_scanning", "bla/bla");
    script_require_udp_ports("Services/udp/unknown", 17);
    script_cve_id("CVE-1999-0524");
    script_require_keys("WMI/Apache/RootPath");
    script_add_preference(name:"Enable Password", type:"password", value:"", id:2);
    script_add_preference(name:"Without ID", type:"password", value:"");
    exit(rc);
}
        "#;
    let storage = Arc::new(DefaultDispatcher::new());
    let key: ContextKey = "test.nasl".into();
    let context = ContextFactory::new(NoOpLoader::default(), storage.clone());
    let mut t = TestBuilder::default()
        .with_context(context)
        .with_context_key(key.clone());
    t.set_variable("description", NaslValue::Number(1));
    t.run_all(code);
    let results = t.results();
    assert_eq!(
        *results.last().unwrap().as_ref().unwrap(),
        NaslValue::Exit(23)
    );

    let mut tag = BTreeMap::new();
    tag.insert(TagKey::CreationDate, 1366091481.into());
    assert_eq!(
        storage
            .retrieve(&key, Retrieve::NVT(None))
            .unwrap()
            .collect::<Vec<_>>(),
        vec![item::Nvt {
            oid: "0.0.0.0.0.0.0.0.0.1".into(),
            name: "that is a very long and descriptive name".into(),
            filename: "test.nasl".into(),
            tag,
            dependencies: vec!["ssh_detect.nasl".into(), "ssh2.nasl".into()],
            required_keys: vec!["WMI/Apache/RootPath".into()],
            mandatory_keys: vec!["ssh/blubb/detected".into()],
            excluded_keys: vec!["Settings/disable_cgi_scanning".into(), "bla/bla".into()],
            required_ports: vec!["Services/ssh".into(), "22".into()],
            required_udp_ports: vec!["Services/udp/unknown".into(), "17".into()],
            references: vec![
                NvtRef {
                    class: "http://freshmeat.sourceforge.net/projects/eventh/".into(),
                    id: "URL".into()
                },
                NvtRef {
                    class: "cve".into(),
                    id: "CVE-1999-0524".into()
                }
            ],
            preferences: vec![
                NvtPreference {
                    id: Some(2),
                    class: Password,
                    name: "Enable Password".into(),
                    default: "".into()
                },
                NvtPreference {
                    id: None,
                    class: Password,
                    name: "Without ID".into(),
                    default: "".into()
                }
            ],
            category: Denial,
            family: "Denial of Service".into()
        }
        .into(),]
    );
}
