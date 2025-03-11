mod error;

use std::ops::Range;

use super::{cursor::Cursor, token::UnclosedTokenKind, Keyword, Token, TokenKind};
use error::TokenizerError;
#[cfg(test)]
use serde::{Deserialize, Serialize};

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
pub struct Tokenizer<'a> {
    // Is used to lookup keywords
    code: &'a str,
    cursor: Cursor<'a>,
    errors: Vec<TokenizerError>,
}

impl<'a> Tokenizer<'a> {
    /// Creates a new Tokenizer
    pub fn tokenize(code: &'a str) -> Result<Vec<Token>, Vec<TokenizerError>> {
        let mut tokenizer = Tokenizer {
            code,
            cursor: Cursor::new(code),
            errors: vec![],
        };
        tokenizer.tokenize_internal().map_err(|_| tokenizer.errors)
    }

    fn tokenize_internal(&mut self) -> Result<Vec<Token>, ()> {
        let mut tokens = vec![];
        while !self.cursor.is_eof() {
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

    /// Returns a reference of a substring within code at given range
    pub fn lookup(&self, range: Range<usize>) -> &'a str {
        &self.code[range]
    }

    // we break out of the macro since > can be parsed to:
    // >>>
    // >>=
    // >>>=
    // >!<
    // most operators don't have triple or tuple variant
    fn tokenize_greater(&mut self) -> TokenKind {
        use TokenKind::*;
        let next = self.cursor.peek(0);
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
                let next = self.cursor.peek(0);
                match next {
                    '>' => {
                        self.cursor.advance();
                        if self.cursor.peek(0) == '=' {
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
            '!' if self.cursor.peek(1) == '<' => {
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
        let next = self.cursor.peek(0);
        match next {
            '=' => {
                self.cursor.advance();
                LessEqual
            }
            '<' => {
                self.cursor.advance();
                let next = self.cursor.peek(0);
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
        let start = self.cursor.len_consumed();
        self.cursor.skip_while(|c| c != '"');
        if self.cursor.is_eof() {
            TokenKind::Unclosed(UnclosedTokenKind::String)
        } else {
            let result = self.code[Range {
                start,
                end: self.cursor.len_consumed(),
            }]
            .to_owned();
            self.cursor.advance();
            TokenKind::String(result)
        }
    }

    // Skips initial and ending string identifier ' || " and verifies that a string is closed
    fn tokenize_data(&mut self) -> TokenKind {
        // we don't want the lookup to contain "
        let start = self.cursor.len_consumed();
        let mut back_slash = false;
        self.cursor.skip_while(|c| {
            if !back_slash && c == '\'' {
                false
            } else {
                back_slash = !back_slash && c == '\\';
                true
            }
        });
        if self.cursor.is_eof() {
            TokenKind::Unclosed(UnclosedTokenKind::Data)
        } else {
            let mut raw_str = self.code[Range {
                start,
                end: self.cursor.len_consumed(),
            }]
            .to_owned();
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
    fn may_parse_ipv4(&mut self, base: NumberBase, start: usize) -> Option<TokenKind> {
        use NumberBase::*;
        // IPv4Address start as Base10
        if base == Base10 && self.cursor.peek(0) == '.' && self.cursor.peek(1).is_numeric() {
            self.cursor.advance();
            self.cursor.skip_while(base.verifier());
            // verify it may be an IPv4Address
            // if the next one is a dot we are at
            // 127.0
            // and need to parse .0
            if self.cursor.peek(0) == '.' {
                if self.cursor.peek(1).is_numeric() {
                    self.cursor.advance();
                    self.cursor.skip_while(base.verifier());
                } else {
                    return Some(TokenKind::IllegalIPv4Address);
                }

                if self.cursor.peek(0) == '.' && self.cursor.peek(1).is_numeric() {
                    self.cursor.advance();
                    self.cursor.skip_while(base.verifier());
                } else {
                    return Some(TokenKind::IllegalIPv4Address);
                }
                return Some(TokenKind::IPv4Address(
                    self.code[Range {
                        start,
                        end: self.cursor.len_consumed(),
                    }]
                    .to_owned(),
                ));
            } else {
                return Some(TokenKind::IllegalIPv4Address);
            }
        }
        None
    }

    // checks if a number is binary, octal, base10 or hex
    fn tokenize_number(&mut self, mut start: usize, current: char) -> TokenKind {
        use NumberBase::*;
        let may_base = {
            if current == '0' {
                match self.cursor.peek(0) {
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
                    if start == self.cursor.len_consumed() {
                        TokenKind::IllegalNumber(base)
                    } else {
                        match i64::from_str_radix(
                            &self.code[Range {
                                start,
                                end: self.cursor.len_consumed(),
                            }],
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
    fn tokenize_identifier(&mut self, start: usize) -> TokenKind {
        self.cursor
            .skip_while(|c| c.is_alphabetic() || c == '_' || c.is_numeric());
        let end = self.cursor.len_consumed();
        let lookup = self.lookup(Range { start, end });
        if lookup != "x" {
            let keyword = Keyword::new(lookup);
            TokenKind::Identifier(keyword)
        } else {
            self.cursor.skip_while(|c| c.is_whitespace());
            if self.cursor.peek(0).is_numeric() {
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
            let next = $cursor.peek(0);
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

impl Tokenizer<'_> {
    fn scan_token(&mut self) -> Result<Token, TokenizerError> {
        use TokenKind::*;
        let start = self.cursor.len_consumed();
        let position = self.cursor.line_column();
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

        let byte_position = (start, self.cursor.len_consumed());
        Ok(Token {
            kind,
            line_column: position,
            position: byte_position,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // use macro instead of a method to have correct line numbers on failure
    macro_rules! verify_tokens {
        ($code:expr, $expected:expr) => {{
            use std::string::String;
            let tokens = Tokenizer::tokenize($code).unwrap();
            let actual: Vec<String> = tokens.iter().map(|t| t.kind().to_string()).collect();
            let expected: Vec<String> = $expected.iter().map(|s| s.to_string()).collect();
            assert_eq!(actual, expected);
        }};
    }

    #[test]
    fn skip_white_space() {
        verify_tokens!("     (       ", ["("]);
    }

    #[test]
    fn single_symbol_tokens() {
        verify_tokens!("(", ["("]);
        verify_tokens!(")", [")"]);
        verify_tokens!("[", ["["]);
        verify_tokens!("]", ["]"]);
        verify_tokens!("{", ["{"]);
        verify_tokens!("}", ["}"]);
        verify_tokens!(",", [","]);
        verify_tokens!(".", ["."]);
        verify_tokens!("-", ["-"]);
        verify_tokens!("+", ["+"]);
        verify_tokens!("%", ["%"]);
        verify_tokens!(";", [";"]);
        verify_tokens!("/", ["/"]);
        verify_tokens!("*", ["*"]);
        verify_tokens!(":", [":"]);
        verify_tokens!("~", ["~"]);
        verify_tokens!("&", ["&"]);
        verify_tokens!("|", ["|"]);
        verify_tokens!("^", ["^"]);
    }

    #[test]
    fn two_symbol_tokens() {
        verify_tokens!("&", ["&"]);
        verify_tokens!("&&", ["&&"]);
        verify_tokens!("|", ["|"]);
        verify_tokens!("||", ["||"]);
        verify_tokens!("!", ["!"]);
        verify_tokens!("!=", ["!="]);
        verify_tokens!("!~", ["!~"]);
        verify_tokens!("=", ["="]);
        verify_tokens!("==", ["=="]);
        verify_tokens!("=~", ["=~"]);
        verify_tokens!(">", [">"]);
        verify_tokens!(">>", [">>"]);
        verify_tokens!(">=", [">="]);
        verify_tokens!("><", ["><"]);
        verify_tokens!("<", ["<"]);
        verify_tokens!("<<", ["<<"]);
        verify_tokens!("<=", ["<="]);
        verify_tokens!("-", ["-"]);
        verify_tokens!("--", ["--"]);
        verify_tokens!("+", ["+"]);
        verify_tokens!("+=", ["+="]);
        verify_tokens!("++", ["++"]);
        verify_tokens!("/", ["/"]);
        verify_tokens!("/=", ["/="]);
        verify_tokens!("*", ["*"]);
        verify_tokens!("**", ["**"]);
        verify_tokens!("*=", ["*="]);
    }

    #[test]
    fn three_symbol_tokens() {
        verify_tokens!(">>>", [">>>"]);
        verify_tokens!(">>=", [">>="]);
        verify_tokens!(">!<", [">!<"]);
        verify_tokens!("<<=", ["<<="]);
    }

    #[test]
    fn four_symbol_tokens() {
        verify_tokens!(">>>=", [">>>="]);
    }

    #[test]
    fn unquotable_string() {
        verify_tokens!(
            "\"hello I am a closed string\\\"",
            ["\"hello I am a closed string\\\""]
        );
        verify_tokens!("\"hello I am a unclosed string\\", ["UnclosedString"]);
    }

    #[test]
    fn quotable_string() {
        verify_tokens!(
            r#"'Hello \\\'you\\\'!'"#,
            ["[72, 101, 108, 108, 111, 32, 92, 39, 121, 111, 117, 92, 39, 33]"]
        );
        verify_tokens!("'Hello \\'you\\'!\\'", ["UnclosedData"]);
    }

    #[test]
    fn numbers() {
        verify_tokens!("0", ["0"]);
        verify_tokens!("0b01", ["1"]);
        verify_tokens!("1234567890", ["1234567890"]);
        verify_tokens!("012345670", ["2739128"]);
        verify_tokens!("0x1234567890ABCDEF", ["1311768467294899695"]);
        // // That would be later illegal because a number if followed by a number
        // // but within tokenizing I think it is the best to ignore that and let it be handled by AST
        verify_tokens!("0b02", ["0", "2"]);
        verify_tokens!("0b2", ["IllegalNumber", "2"]);
    }

    #[test]
    fn single_line_comments() {
        verify_tokens!("# this is a comment\n;", [";"]);
    }

    #[test]
    fn identifier() {
        verify_tokens!("help_lo", ["help_lo"]);
        verify_tokens!("_hello", ["_hello"]);
        verify_tokens!("_h4llo", ["_h4llo"]);
        verify_tokens!("4_h4llo", ["4", "_h4llo",]);
    }

    #[test]
    fn keywords() {
        verify_tokens!("for", ["for"]);
        verify_tokens!("foreach", ["foreach"]);
        verify_tokens!("if", ["if"]);
        verify_tokens!("else", ["else"]);
        verify_tokens!("while", ["while"]);
        verify_tokens!("repeat", ["repeat"]);
        verify_tokens!("until", ["until"]);
        verify_tokens!("local_var", ["local_var"]);
        verify_tokens!("global_var", ["global_var"]);
        verify_tokens!("NULL", ["NULL"]);
        verify_tokens!("return", ["return"]);
        verify_tokens!("include", ["include"]);
        verify_tokens!("exit", ["exit"]);
        verify_tokens!("break", ["break"]);
        verify_tokens!("continue", ["continue"]);
    }

    #[test]
    fn string_quoting() {
        verify_tokens!(
            r"'webapps\\\\appliance\\\\'",
            [
                r"[119, 101, 98, 97, 112, 112, 115, 92, 92, 97, 112, 112, 108, 105, 97, 110, 99, 101, 92, 92]",
            ]
        );
    }

    #[test]
    fn data_escape_quoting() {
        verify_tokens!(
            r#"'version=\"1.0\"'"#,
            [r"[118, 101, 114, 115, 105, 111, 110, 61, 34, 49, 46, 48, 34]",]
        );
    }

    #[test]
    fn simplified_ipv4_address() {
        verify_tokens!("10.187.76.12", ["10.187.76.12",]);
    }

    #[test]
    fn repeat_x_times() {
        verify_tokens!("x() x 10;", ["x", "(", ")", "X", "10", ";"]);
    }
}
