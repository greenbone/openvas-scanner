///! This module defines the Cursor as a basis for tokenizing
use std::str::Chars;

pub const EOF_CHAR: char = '\0';

/// Peekable iterator over a char sequence.
///
/// Next characters can be peeked via `peek` method,
/// and position can be shifted forward via `bump` method.
pub struct Cursor<'a> {
    /// is needed to calculate the length when e.g. tokenizing
    initial_len: usize,
    chars: Chars<'a>,
}

impl<'a> Cursor<'a> {
    /// Returns a new cursor based on given input
    pub fn new(input: &'a str) -> Cursor<'a> {
        Cursor {
            initial_len: input.len(),
            chars: input.chars(),
        }
    }

    /// Peeks the nth next characher or returns EOF_CHAR when unreachable
    pub fn peek(&self, n: usize) -> char {
        let mut iter = self.chars.clone();
        for _ in 0..n {
            iter.next();
        }
        iter.next().unwrap_or(EOF_CHAR)
    }

    /// Returns the next char or None if at the end
    pub fn bump(&mut self) -> Option<char> {
        self.chars.next()
    }

    /// Returns true when the Cursor is at the end of the initial input
    pub fn is_eof(&self) -> bool {
        self.chars.as_str().is_empty()
    }

    /// Skips characters until the given predicate returns true
    pub fn skip_while(&mut self, mut predicate: impl FnMut(char) -> bool) {
        while predicate(self.peek(0)) && !self.is_eof() {
            self.bump();
        }
    }

    /// Returns amount of already consumed symbols.
    pub fn len_consumed(&self) -> usize {
        self.initial_len - self.chars.as_str().len()
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Range;

    use super::*;

    #[test]
    fn peek() {
        let mut crsr = Cursor::new("a = \"test\";");
        assert_eq!(crsr.peek(2), '=');
        assert_eq!(crsr.bump(), Some('a'));
    }

    #[test]
    fn skip_whitespaces() {
        let mut crsr = Cursor::new("    a = \"test\";");
        crsr.skip_while(|c| c.is_ascii_whitespace());
        assert_eq!(crsr.bump(), Some('a'));
    }

    #[test]
    fn eof() {
        let mut crsr = Cursor::new("a = \"test\";");
        crsr.skip_while(|c|c != ';');
        assert!(!crsr.is_eof());
        crsr.bump();
        assert!(crsr.is_eof());
    }

    #[test]
    fn gather_string_literal() {
        let code = "a = \"test\";";
        let mut crsr = Cursor::new(code);
        // skip to "
        crsr.skip_while(|c| c != '"');
        // jump over "
        crsr.bump();
        // remember previosuly consumed
        let pconsumed = crsr.len_consumed();
        crsr.skip_while(|c| c != '"');
        // get string within the range
        let actual = &code[Range {
            start: pconsumed,
            end: crsr.len_consumed(),
        }];
        assert_eq!(actual, "test");
    }
}
