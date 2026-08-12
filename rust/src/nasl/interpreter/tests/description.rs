// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::storage::Retriever;
use crate::storage::inmemory::InMemoryStorage;
use crate::storage::items::nvt::FileName;

use std::sync::Arc;

use crate::nasl::test_prelude::*;

#[tokio::test]
async fn description() {
    let code = r#"
rc = 23;
if(description)
{
    script_oid("0.0.0.0.0.0.0.0.0.1");
    script_version("2022-11-14T13:47:12+0000");
    script_tag(name:"creation_date", value:"2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)");
    script_name("name");
    script_category(ACT_DENIAL);
    script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
    script_family("Denial of Service");
    script_dependencies("ssh_detect.nasl", "ssh2.nasl");
    script_require_ports("Services/ssh", 22);
    script_mandatory_keys("ssh/foo/detected");
    script_xref(name:"URL", value:"http://freshmeat.sourceforge.net/projects/eventh/");
    script_exclude_keys("Settings/disable_cgi_scanning", "bar/baz");
    script_require_udp_ports("Services/udp/unknown", 17);
    script_cve_id("CVE-1999-0524");
    script_require_keys("WMI/Apache/RootPath");
    script_add_preference(name:"Enable Password", type:"password", value:"", id:2);
    script_add_preference(name:"Without ID", type:"password", value:"");
    exit(rc);
}
        "#;
    let storage = Arc::new(InMemoryStorage::new());
    let key = FileName("test.nasl".to_string());
    let mut t = TestBuilder::from_storage(storage.clone()).with_filename(key.0.clone().into());
    t.set_variable("description", NaslValue::Number(1));
    t.run_all(code);
    let results = t.results();
    t.async_verify().await;
    assert_eq!(
        *results.last().unwrap().as_ref().unwrap(),
        NaslValue::Exit(23)
    );

    let nvt = storage.retrieve(&key).await.unwrap().unwrap();
    insta::assert_ron_snapshot!(nvt);
}
