#[cfg(test)]
mod test {

    use core::panic;
    use std::{env, fs, ops::Range};

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

    #[test]
    fn edge_cases() {
        let mut current = env::current_dir().unwrap();
        current.push("tests/test.nasl");

        let code: String = fs::read(current.clone())
            .map(|bs| bs.iter().map(|&b| b as char).collect())
            .unwrap();
        for i in parse(&code) {
            match i {
                Ok(_) => {},
                Err(err) => {
                    if let Some((line, character)) = to_line(&code, err.clone()) {
                        panic!("{} unexpected character {} in {:?}", line, character, current);
                    } else {
                        panic!("{}", err);
                    }
                }
            }
        }
    }
}
