mod error;
#[cfg(test)]
mod tests;

use std::ops::AddAssign;

use super::{token::UnclosedTokenKind, Keyword, Token, TokenKind};
use error::{TokenizerError, TokenizerErrorKind};
#[cfg(test)]
use serde::{Deserialize, Serialize};

#[derive(Copy, Default, Clone, Debug, PartialEq, Eq)]
pub struct CharIndex(pub usize);

impl AddAssign<usize> for CharIndex {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs
    }
}

struct Cursor {
    chars: Vec<char>,
    position: CharIndex,
    line: usize,
    col: usize,
}

impl Cursor {
    fn new(code: &str) -> Self {
        Self {
            chars: code.chars().collect(),
            position: CharIndex(0),
            line: 1,
            col: 1,
        }
    }

    fn is_at_eof(&self) -> bool {
        self.position.0 == self.chars.len()
    }

    fn peek(&self) -> char {
        self.peek_ahead(0)
    }

    fn peek_ahead(&self, ahead: usize) -> char {
        const EOF_CHAR: char = '\0';
        self.chars
            .get(self.position.0 + ahead)
            .copied()
            .unwrap_or(EOF_CHAR)
    }

    fn advance(&mut self) -> Option<char> {
        let result = self.chars.get(self.position.0).copied();
        self.position.0 += 1;
        match result {
            Some('\n') => {
                self.line += 1;
                self.col = 1;
            }
            Some(_) => {
                self.col += 1;
            }
            _ => {}
        }
        result
    }

    fn position(&self) -> CharIndex {
        self.position
    }

    /// Skips characters while given predicate returns true
    fn skip_while(&mut self, mut predicate: impl FnMut(char) -> bool) {
        while !self.is_at_eof() && predicate(self.peek()) {
            self.advance();
        }
    }
}

/// Identifies if number is base10, base 8, hex or binary
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Serialize, Deserialize))]
pub enum NumberBase {
    /// Base 2: contains 01 is defined by 0b e.g.: `0b010101`
    Binary,
    /// Base 8: contains 0-8 is defined by a starting 0 e.g.: `0123456780`
    Octal,
    /// Base 10: contains 0-9 is the default e.g.: `1234567890`
    Base10,
    /// Base 16: contains 0-9A-F is defined by a starting 0x e.g.: `0x123456789ABCDEF0`
    Hex,
}

impl NumberBase {
    fn verify_binary(peeked: char) -> bool {
        peeked == '0' || peeked == '1'
    }

    fn verify_octal(peeked: char) -> bool {
        ('0'..='7').contains(&peeked)
    }

    fn verify_base10(peeked: char) -> bool {
        peeked.is_ascii_digit()
    }

    fn verify_hex(peeked: char) -> bool {
        peeked.is_ascii_hexdigit()
    }
    pub(crate) fn verifier(self) -> impl Fn(char) -> bool {
        match self {
            Self::Binary => Self::verify_binary,
            Self::Octal => Self::verify_octal,
            Self::Base10 => Self::verify_base10,
            Self::Hex => Self::verify_hex,
        }
    }

    /// Returns the radix
    pub fn radix(&self) -> u32 {
        match self {
            NumberBase::Binary => 2,
            NumberBase::Octal => 8,
            NumberBase::Base10 => 10,
            NumberBase::Hex => 16,
        }
    }
}

/// Tokenizer uses a cursor to create tokens
pub struct Tokenizer {
    cursor: Cursor,
    begin_match_position: CharIndex,
    errors: Vec<TokenizerError>,
}

impl Tokenizer {
    /// Creates a new Tokenizer
    pub fn tokenize(code: &str) -> Result<Vec<Token>, Vec<TokenizerError>> {
        let mut tokenizer = Tokenizer {
            errors: vec![],
            cursor: Cursor::new(code),
            begin_match_position: CharIndex::default(),
        };
        tokenizer.tokenize_internal().map_err(|_| tokenizer.errors)
    }

    fn tokenize_internal(&mut self) -> Result<Vec<Token>, ()> {
        let mut tokens = vec![];
        while !self.cursor.is_at_eof() {
            let token = self.scan_token();
            match token {
                Ok(token) => {
                    if token.is_relevant() {
                        tokens.push(token)
                    }
                }
                Err(err) => {
                    self.errors.push(err);
                }
            }
        }
        if self.errors.is_empty() {
            Ok(tokens)
        } else {
            Err(())
        }
    }

    pub fn match_error(&self, kind: TokenizerErrorKind) -> TokenizerError {
        TokenizerError {
            kind,
            range: self.begin_match_position.0 - 1..self.cursor.position().0,
        }
    }

    fn substring(&self, start: CharIndex, end: CharIndex) -> String {
        self.cursor.chars[start.0..end.0].iter().collect()
    }

    // we break out of the macro since > can be parsed to:
    // >>>
    // >>=
    // >>>=
    // >!<
    // most operators don't have triple or tuple variant
    fn tokenize_greater(&mut self) -> TokenKind {
        use TokenKind::*;
        let next = self.cursor.peek();
        match next {
            '=' => {
                self.cursor.advance();
                GreaterEqual
            }
            '<' => {
                self.cursor.advance();
                GreaterLess
            }
            '>' => {
                self.cursor.advance();
                let next = self.cursor.peek();
                match next {
                    '>' => {
                        self.cursor.advance();
                        if self.cursor.peek() == '=' {
                            self.cursor.advance();
                            return GreaterGreaterGreaterEqual;
                        }

                        GreaterGreaterGreater
                    }
                    '=' => {
                        self.cursor.advance();
                        GreaterGreaterEqual
                    }
                    _ => GreaterGreater,
                }
            }
            '!' if self.cursor.peek_ahead(1) == '<' => {
                self.cursor.advance();
                self.cursor.advance();
                GreaterBangLess
            }
            _ => Greater,
        }
    }

    // we break out of the macro since < can be parsed to:
    // <<=
    // most operators don't have triple or tuple variant
    fn tokenize_less(&mut self) -> TokenKind {
        use TokenKind::*;
        let next = self.cursor.peek();
        match next {
            '=' => {
                self.cursor.advance();
                LessEqual
            }
            '<' => {
                self.cursor.advance();
                let next = self.cursor.peek();
                match next {
                    '=' => {
                        self.cursor.advance();
                        LessLessEqual
                    }
                    _ => LessLess,
                }
            }
            _ => Less,
        }
    }

    // Skips initial and ending data identifier ' and verifies that a string is closed
    fn tokenize_string(&mut self) -> TokenKind {
        let start = self.cursor.position();
        self.cursor.skip_while(|c| c != '"');
        if self.cursor.is_at_eof() {
            TokenKind::Unclosed(UnclosedTokenKind::String)
        } else {
            let result = self.substring(start, self.cursor.position());
            self.cursor.advance();
            TokenKind::String(result)
        }
    }

    // Skips initial and ending string identifier ' || " and verifies that a string is closed
    fn tokenize_data(&mut self) -> TokenKind {
        // we don't want the lookup to contain "
        let start = self.cursor.position();
        let mut back_slash = false;
        self.cursor.skip_while(|c| {
            if !back_slash && c == '\'' {
                false
            } else {
                back_slash = !back_slash && c == '\\';
                true
            }
        });
        if self.cursor.is_at_eof() {
            TokenKind::Unclosed(UnclosedTokenKind::Data)
        } else {
            let mut raw_str = self.substring(start, self.cursor.position());
            raw_str = raw_str.replace(r#"\""#, "\"");
            raw_str = raw_str.replace(r#"\n"#, "\n");
            raw_str = raw_str.replace(r"\\", "\\");
            raw_str = raw_str.replace(r"\'", "'");
            raw_str = raw_str.replace(r"\r", "\r");
            raw_str = raw_str.replace(r"\t", "\t");
            self.cursor.advance();
            TokenKind::Data(raw_str.as_bytes().to_vec())
        }
    }
    fn may_parse_ipv4(&mut self, base: NumberBase, start: CharIndex) -> Option<TokenKind> {
        use NumberBase::*;
        // IPv4Address start as Base10
        if base == Base10 && self.cursor.peek() == '.' && self.cursor.peek_ahead(1).is_numeric() {
            self.cursor.advance();
            self.cursor.skip_while(base.verifier());
            // verify it may be an IPv4Address
            // if the next one is a dot we are at
            // 127.0
            // and need to parse .0
            if self.cursor.peek() == '.' {
                if self.cursor.peek_ahead(1).is_numeric() {
                    self.cursor.advance();
                    self.cursor.skip_while(base.verifier());
                } else {
                    return Some(TokenKind::IllegalIPv4Address);
                }

                if self.cursor.peek() == '.' && self.cursor.peek_ahead(1).is_numeric() {
                    self.cursor.advance();
                    self.cursor.skip_while(base.verifier());
                } else {
                    return Some(TokenKind::IllegalIPv4Address);
                }
                return Some(TokenKind::IPv4Address(
                    self.substring(start, self.cursor.position()),
                ));
            } else {
                return Some(TokenKind::IllegalIPv4Address);
            }
        }
        None
    }

    // checks if a number is binary, octal, base10 or hex
    fn tokenize_number(&mut self, mut start: CharIndex, current: char) -> TokenKind {
        use NumberBase::*;
        let may_base = {
            if current == '0' {
                match self.cursor.peek() {
                    'b' => {
                        // jump over non numeric
                        self.cursor.advance();
                        // we don't need `0b` later
                        start += 2;
                        Some(Binary)
                    }
                    'x' => {
                        // jump over non numeric
                        self.cursor.advance();
                        // we don't need `0x` later
                        start += 2;
                        Some(Hex)
                    }
                    peeked if ('0'..='7').contains(&peeked) => {
                        // we don't need leading 0 later
                        start += 1;
                        Some(Octal)
                    }
                    peeked if peeked.is_alphabetic() => None,
                    _ => Some(Base10),
                }
            } else {
                Some(Base10)
            }
        };
        if let Some(base) = may_base {
            self.cursor.skip_while(base.verifier());
            match self.may_parse_ipv4(base, start) {
                Some(token) => token,
                None => {
                    // we verify that the cursor actually moved to prevent scenarios like
                    // 0b without any actual number in it
                    if start == self.cursor.position() {
                        TokenKind::IllegalNumber(base)
                    } else {
                        match i64::from_str_radix(
                            &self.substring(start, self.cursor.position()),
                            base.radix(),
                        ) {
                            Ok(num) => TokenKind::Number(num),
                            Err(_) => TokenKind::IllegalNumber(base),
                        }
                    }
                }
            }
        } else {
            TokenKind::UnknownBase
        }
    }

    // Checks if an identifier is a Keyword or not
    fn tokenize_identifier(&mut self, start: CharIndex) -> TokenKind {
        self.cursor
            .skip_while(|c| c.is_alphabetic() || c == '_' || c.is_numeric());
        let end = self.cursor.position();
        let lookup = self.substring(start, end);
        if lookup != "x" {
            let keyword = Keyword::new(&lookup);
            TokenKind::Identifier(keyword)
        } else {
            self.cursor.skip_while(|c| c.is_whitespace());
            if self.cursor.peek().is_numeric() {
                TokenKind::X
            } else {
                TokenKind::Identifier(Keyword::Undefined(lookup.to_owned()))
            }
        }
    }
}

// Is used to simplify cases for double_tokens, instead of having to rewrite each match case for each double_token
// this macro can be used:
//'+' => double_token!(self.cursor, start, '+', '+', PlusPlus, '=', PlusEqual),
// within the Iterator implementation of Tokenizer
macro_rules! two_symbol_token {
    ($cursor:expr, $start:tt, $single_symbol:tt, $($matching_char:tt, $two_symbol_token:expr ), *) => {
        {
            let next = $cursor.peek();
            match next {
                $($matching_char => {
                  $cursor.advance();
                  $two_symbol_token
                }, )*
                _ => $single_symbol,
            }
        }
    };
}

impl Tokenizer {
    fn scan_token(&mut self) -> Result<Token, TokenizerError> {
        use TokenKind::*;
        let start = self.cursor.position();
        self.begin_match_position = start;
        let line_column = (self.cursor.line, self.cursor.col);
        // We can unwrap here, since we check that we're not at EOF before calling scan_token.
        let kind = match self.cursor.advance().unwrap() {
            '(' => LeftParen,
            ')' => RightParen,
            '[' => LeftBrace,
            ']' => RightBrace,
            '{' => LeftCurlyBracket,
            '}' => RightCurlyBracket,
            ',' => Comma,
            '.' => Dot,
            '#' => {
                self.cursor.skip_while(|c| c != '\n');
                Comment
            }
            '-' => two_symbol_token!(self.cursor, start, Minus, '-', MinusMinus, '=', MinusEqual),
            '+' => {
                two_symbol_token!(self.cursor, start, Plus, '+', PlusPlus, '=', PlusEqual)
            }
            '%' => two_symbol_token!(self.cursor, start, Percent, '=', PercentEqual),
            ';' => Semicolon,
            '/' => two_symbol_token!(self.cursor, start, Slash, '=', SlashEqual), /* self.tokenize_slash(start), */
            '*' => {
                two_symbol_token!(self.cursor, start, Star, '*', StarStar, '=', StarEqual)
            }
            ':' => DoublePoint,
            '~' => Tilde,
            '&' => {
                two_symbol_token!(self.cursor, start, Ampersand, '&', AmpersandAmpersand)
            }
            '|' => two_symbol_token!(self.cursor, start, Pipe, '|', PipePipe),
            '^' => Caret,
            '!' => {
                two_symbol_token!(self.cursor, start, Bang, '=', BangEqual, '~', BangTilde)
            }
            '=' => two_symbol_token!(self.cursor, start, Equal, '=', EqualEqual, '~', EqualTilde),
            '>' => self.tokenize_greater(),
            '<' => self.tokenize_less(),
            '"' => self.tokenize_string(),
            '\'' => self.tokenize_data(),
            c if c.is_ascii_digit() => self.tokenize_number(start, c),
            c if c.is_alphabetic() || c == '_' => self.tokenize_identifier(start),
            c if c.is_whitespace() => Whitespace,
            _ => UnknownSymbol,
        };

        Ok(Token {
            kind,
            line_column,
            position: (start.0, self.cursor.position().0),
        })
    }
}
