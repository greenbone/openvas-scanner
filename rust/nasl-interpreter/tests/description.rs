#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use nasl_interpreter::{Storage, Interpreter, ContextType, NaslValue, error::InterpetError};
    use nasl_syntax::parse;

    struct MockStrorage {
        map: HashMap<String, String>,
    }

    impl MockStrorage {
        fn new() -> Self {
            MockStrorage {
                map: HashMap::new(),
            }
        }
    }
    impl Storage for MockStrorage {
        fn write(&mut self, key: &str, value: &str) {
            self.map.insert(key.to_string(), value.to_string());
        }
        fn read(&self, key: &str) -> Option<&str> {
            if self.map.contains_key(key) {
                return Some(self.map[key].as_str());
            }
            None
        }
    }


    #[test]
    fn description() -> Result<(), InterpetError>{
        let code = r###"
if(description)
{
  script_oid("0.0.0.0.0.0.0.0.0.1");
  script_version("2022-11-14T13:47:12+0000");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-11-14 13:47:12 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2013-04-16 11:21:21 +0530 (Tue, 16 Apr 2013)");
  script_name("that is a very long and descriptive name");

# script_category values should be a keyword
#  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
# script_dependencies can have multiple entries
#  script_dependencies("ssh_detect.nasl");
#  script_require_ports("Services/ssh", 22);
# same as script_dependencies
#  script_mandatory_keys("ssh/blubb/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to destroy the world. Lets sing the doom song now.");

  script_tag(name:"affected", value:"Everything.");

  script_tag(name:"insight", value:"The flaw is very risky...
  ...
  quasi exponential. Doom.");

  script_tag(name:"solution", value:"Upgrade.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This triggered by something, probably sending bytes");

  exit(0);
}
        "###;
        let mut storage= MockStrorage::new();
        let initial = vec![("description".to_owned(), ContextType::Value(NaslValue::Number(1)))];
        let mut interpret = Interpreter::new(&mut storage, initial, code);
        for stmt in parse(code) {
            let stmt = stmt?;
            assert_eq!(interpret.resolve(stmt)?, NaslValue::Exit(0));
        }
        assert_eq!(storage.read("oid"), Some("0.0.0.0.0.0.0.0.0.1"));
        // TODO same for the others
        Ok(())
    }

}
