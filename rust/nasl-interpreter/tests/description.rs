// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use nasl_syntax::{LoadError, Loader};

#[derive(Default)]
pub struct NoOpLoader {}

/// Is a no operation loader for test purposes.
impl Loader for NoOpLoader {
    fn load(&self, _: &str) -> Result<String, LoadError> {
        Ok(String::default())
    }

    fn root_path(&self) -> Result<std::string::String, nasl_syntax::LoadError> {
        Ok(String::default())
    }
}

#[cfg(test)]
mod tests {

    use std::collections::BTreeMap;

    use nasl_builtin_utils::Context;
    use nasl_builtin_utils::ContextType;
    use nasl_builtin_utils::Register;
    use nasl_interpreter::InterpretError;
    use nasl_interpreter::Interpreter;

    use nasl_syntax::parse;
    use nasl_syntax::NaslValue;

    use storage::item;
    use storage::item::NvtPreference;
    use storage::item::NvtRef;
    use storage::item::PreferenceType::*;
    use storage::item::ACT::Denial;
    use storage::DefaultDispatcher;
    use storage::Retriever;

    use crate::NoOpLoader;

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
        let storage = DefaultDispatcher::new(true);
        let loader = NoOpLoader::default();
        let initial = [(
            "description".to_owned(),
            ContextType::Value(NaslValue::Number(1)),
        )];
        let register = Register::root_initial(&initial);
        let key: storage::ContextKey = "test.nasl".into();
        let target = String::new();
        let functions = nasl_builtin_std::nasl_std_functions();
        let ctxconfigs = Context::new(key.clone(), target, &storage, &storage, &loader, &functions);
        let mut interpreter = Interpreter::new(register, &ctxconfigs);
        let results = parse(code)
            .map(|stmt| match stmt {
                Ok(stmt) => interpreter.retry_resolve_next(&stmt, 1),
                Err(r) => Err(InterpretError::from(r)),
            })
            .last()
            // for the case of NaslValue that returns nothing
            .unwrap_or(Ok(NaslValue::Exit(0)));
        assert_eq!(results, Ok(NaslValue::Exit(23)));

        let mut tag = BTreeMap::new();
        tag.insert(storage::item::TagKey::CreationDate, 1366091481.into());
        assert_eq!(
            storage
                .retrieve(&key, storage::Retrieve::NVT(None))
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
}
