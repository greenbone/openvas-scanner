use nasl_interpreter::{LoadError, Loader};

#[derive(Default)]
pub struct NoOpLoader {}

/// Is a no operation loader for test purposes.
impl Loader for NoOpLoader {
    fn load(&self, _: &str) -> Result<String, LoadError> {
        Ok(String::default())
    }
}

#[cfg(test)]
mod tests {

    use nasl_interpreter::{ContextType, InterpretError, NaslValue};
    use nasl_interpreter::{Interpreter, Register};

    use nasl_syntax::parse;
    use sink::nvt::NvtRef;
    use sink::nvt::TagKey::*;
    use sink::nvt::ACT::*;
    use sink::nvt::{NVTField::*, NvtPreference, PreferenceType};
    use sink::DefaultSink;
    use sink::Dispatch::NVT;
    use sink::Sink;

    use crate::NoOpLoader;

    #[test]
    fn description() {
        let code = r###"
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
        "###;
        let storage = DefaultSink::new(true);
        let loader = NoOpLoader::default();
        let key = "test.nasl";
        let initial = vec![(
            "description".to_owned(),
            ContextType::Value(NaslValue::Number(1)),
        )];
        storage
            .dispatch(
                key,
                sink::Dispatch::NVT(sink::nvt::NVTField::FileName(key.to_owned())),
            )
            .expect("storage should work");
        let mut register = Register::root_initial(initial);
        let mut interpreter = Interpreter::new(key, &storage, &loader, &mut register);
        let results = parse(code)
            .map(|stmt| match stmt {
                Ok(stmt) => interpreter.resolve(&stmt),
                Err(r) => Err(InterpretError::from(r)),
            })
            .last()
            // for the case of NaslValue that returns nothing
            .unwrap_or(Ok(NaslValue::Exit(0)));
        assert_eq!(results, Ok(NaslValue::Exit(23)));
        assert_eq!(
            &storage
                .retrieve("test.nasl", sink::Retrieve::NVT(None))
                .unwrap(),
            &vec![
                NVT(FileName("test.nasl".to_owned())),
                NVT(Oid("0.0.0.0.0.0.0.0.0.1".to_owned())),
                NVT(NoOp),
                NVT(Tag(
                    CreationDate,
                    "2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)".to_owned()
                )),
                NVT(Name("that is a very long and descriptive name".to_owned())),
                NVT(Category(Denial)),
                NVT(NoOp),
                NVT(Family("Denial of Service".to_owned())),
                NVT(Dependencies(vec![
                    "ssh_detect.nasl".to_owned(),
                    "ssh2.nasl".to_owned()
                ])),
                NVT(RequiredPorts(vec![
                    "Services/ssh".to_owned(),
                    "22".to_owned()
                ])),
                NVT(MandatoryKeys(vec!["ssh/blubb/detected".to_owned()])),
                NVT(Reference(NvtRef {
                    class: "http://freshmeat.sourceforge.net/projects/eventh/".to_owned(),
                    id: "URL".to_owned(),
                    text: None
                })),
                NVT(ExcludedKeys(vec![
                    "Settings/disable_cgi_scanning".to_owned(),
                    "bla/bla".to_owned()
                ])),
                NVT(RequiredUdpPorts(vec![
                    "Services/udp/unknown".to_owned(),
                    "17".to_owned()
                ])),
                NVT(Reference(NvtRef {
                    class: "cve".to_owned(),
                    id: "CVE-1999-0524".to_owned(),
                    text: None
                })),
                NVT(RequiredKeys(vec!["WMI/Apache/RootPath".to_owned()])),
                NVT(Preference(NvtPreference {
                    id: Some(2),
                    class: PreferenceType::Password,
                    name: "Enable Password".to_owned(),
                    default: "".to_owned()
                })),
                NVT(Preference(NvtPreference {
                    id: None,
                    class: PreferenceType::Password,
                    name: "Without ID".to_owned(),
                    default: "".to_owned()
                })),
            ]
        );
    }
}
