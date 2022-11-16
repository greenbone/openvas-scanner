#[cfg(test)]
mod test {

    use core::panic;
    use std::{
        env,
        fs::{self, DirEntry},
        io,
        ops::Range,
        path::{Path, PathBuf},
        str::FromStr,
    };

    use nasl_syntax::{parse, Statement, SyntaxError};

    fn get_range(err: &SyntaxError) -> Option<Range<usize>> {
        if let Some(token) = err.token {
            Some(token.range())
        } else if let Some(stmt) = err.clone().statement {
            let token = {
                match stmt {
                    Statement::Primitive(token) => token,
                    Statement::Array(token, _) => token,
                    _ => return None,
                }
            };
            Some(token.range())
        } else {
            None
        }
    }
    fn to_line(code: &str, err: SyntaxError) -> Option<(usize, String)> {
        if let Some(range) = get_range(&err) {
            let character = code[range.clone()].to_owned();
            let line = code[Range {
                start: 0,
                end: range.end,
            }]
            .as_bytes()
            .iter()
            .filter(|&&c| c == b'\n')
            .count();
            // we start at 0 but editors start 1
            Some((line + 1, character))
        } else {
            None
        }
    }
    // one possible implementation of walking a directory only visiting files
    fn visit_dirs(dir: &Path, cb: &dyn Fn(&DirEntry)) -> io::Result<()> {
        if dir.is_dir() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit_dirs(&path, cb)?;
                } else {
                    cb(&entry);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn edge_cases() {
        let mut current = env::current_dir().unwrap();
        current.push("tests/test2.nasl");
        let code: String = fs::read(current.clone())
            .map(|bs| bs.iter().map(|&b| b as char).collect())
            .unwrap();
        for i in parse(&code) {
            match i {
                Ok(_) => {}
                Err(err) => {
                    if let Some((line, character)) = to_line(&code, err.clone()) {
                        panic!(
                            "{} unexpected character {} in {:?}",
                            line, character, current,
                        );
                    } else {
                        panic!("{}", err);
                    }
                }
            }
        }
    }
    #[ignore]
    #[test]
    fn skimp_all() {
        let wd =
            PathBuf::from_str("/Users/philippeder/src/greenbone/vulnerability-tests/nasl/common/")
                .unwrap();
        visit_dirs(wd.as_path(), &|entry| {
            println!("PARSING {:?}", entry.path());
            let code: String = fs::read(entry.path())
                .map(|bs| bs.iter().map(|&b| b as char).collect())
                .unwrap();
            for i in parse(&code) {
                match i {
                    Ok(_) => {}
                    Err(err) => {
                        if let Some((line, character)) = to_line(&code, err.clone()) {
                            panic!(
                                "{} unexpected character {} in {:?}",
                                line,
                                character,
                                entry.path(),
                            );
                        } else {
                            panic!("{}", err);
                        }
                    }
                }
            }
        })
        .unwrap();
    }
}
