mod error;
#[cfg(test)]
mod tests;

use std::ops::{Add, AddAssign, Sub};

use crate::nasl::{error::Span, syntax::token::Literal};

use super::{Ident, Keyword, Token, TokenKind, token::LiteralKind};
pub use error::{TokenizerError, TokenizerErrorKind};

#[derive(Copy, Default, Clone, Debug, PartialEq, Eq)]
pub struct CharIndex(pub usize);

impl AddAssign<usize> for CharIndex {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += rhs
    }
}

impl Add<usize> for CharIndex {
    type Output = CharIndex;

    fn add(self, rhs: usize) -> Self {
        CharIndex(self.0 + rhs)
    }
}

impl Sub<usize> for CharIndex {
    type Output = CharIndex;

    fn sub(self, rhs: usize) -> Self {
        CharIndex(self.0 - rhs)
    }
}

#[derive(Clone)]
struct Cursor {
    chars: Vec<char>,
    position: CharIndex,
}

impl Cursor {
    fn new(code: &str) -> Self {
        Self {
            chars: code.chars().collect(),
            position: CharIndex(0),
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

    /// Skips characters while given predicate returns true. Returns
    /// the given error kind if no character was skipped.
    fn consume_while(
        &mut self,
        predicate: impl FnMut(char) -> bool,
        e: TokenizerErrorKind,
    ) -> Result<(), TokenizerErrorKind> {
        let pos = self.position;
        self.skip_while(predicate);
        if pos == self.position {
            // Advance to set the error position correctly.
            self.advance();
            Err(e)
        } else {
            Ok(())
        }
    }

    fn span_from(&self, start: CharIndex) -> Span {
        Span::new(start, self.position)
    }
}

/// Identifies if number is base10, base 8, hex or binary
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NumberBase {
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
    fn radix(&self) -> u32 {
        match self {
            NumberBase::Binary => 2,
            NumberBase::Octal => 8,
            NumberBase::Base10 => 10,
            NumberBase::Hex => 16,
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

/// Tokenizer uses a cursor to create tokens
// TODO remove clone?
#[derive(Clone)]
pub struct Tokenizer {
    cursor: Cursor,
    begin_match_position: CharIndex,
}

impl Tokenizer {
    /// Creates a new Tokenizer
    pub fn tokenize(code: &str) -> Self {
        Tokenizer {
            cursor: Cursor::new(code),
            begin_match_position: CharIndex::default(),
        }
    }

    pub fn advance(&mut self) -> Result<Token, TokenizerError> {
        while !self.cursor.is_at_eof() {
            let token = self.scan_token();
            match token {
                Ok(Some(token)) => return Ok(token),
                Ok(None) => {
                    // Encountered whitespace or a comment, ignore it.
                }
                Err(err) => return Err(err),
            }
        }
        let position = self.cursor.position();
        Ok(Token::new(
            TokenKind::Eof,
            Span::new(position, position + 1),
        ))
    }

    fn consume(&mut self, expected: char, f: TokenizerErrorKind) -> Result<(), TokenizerErrorKind> {
        if self.cursor.peek() != expected {
            self.cursor.advance();
            Err(f)
        } else {
            self.cursor.advance();
            Ok(())
        }
    }

    fn scan_token(&mut self) -> Result<Option<Token>, TokenizerError> {
        use TokenKind::*;
        let start = self.cursor.position();
        // We can unwrap here, since we check that we're not at EOF before calling scan_token.
        let char = self.cursor.advance().unwrap();
        self.begin_match_position = self.cursor.position();
        let kind = match char {
            '(' => LeftParen,
            ')' => RightParen,
            '[' => LeftBracket,
            ']' => RightBracket,
            '{' => LeftBrace,
            '}' => RightBrace,
            ',' => Comma,
            '.' => Dot,
            '#' => {
                self.cursor.skip_while(|c| c != '\n');
                return Ok(None);
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
            ':' => Colon,
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
            '"' => self.tokenize_string()?,
            '\'' => self.tokenize_data()?,
            c if c.is_ascii_digit() => self.tokenize_number(start, c)?,
            c if c.is_alphabetic() || c == '_' => self.tokenize_identifiers(start),
            c if c.is_whitespace() => return Ok(None),
            _ => return Err(self.error(TokenizerErrorKind::InvalidCharacter)),
        };

        Ok(Some(Token::new(
            kind,
            Span::new(start, self.cursor.position()),
        )))
    }

    fn error(&self, kind: TokenizerErrorKind) -> TokenizerError {
        TokenizerError {
            kind,
            span: Span::new(self.begin_match_position - 1, self.cursor.position()),
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
    fn tokenize_string(&mut self) -> Result<TokenKind, TokenizerError> {
        let start = self.cursor.position();
        self.cursor.skip_while(|c| c != '"');
        if self.cursor.is_at_eof() {
            Err(self.error(TokenizerErrorKind::UnclosedString))
        } else {
            let result = self.substring(start, self.cursor.position());
            self.cursor.advance();
            Ok(TokenKind::Literal(Literal::new(
                LiteralKind::String(result),
                self.cursor.span_from(start - 1),
            )))
        }
    }

    // Skips initial and ending string identifier ' || " and verifies that a string is closed
    fn tokenize_data(&mut self) -> Result<TokenKind, TokenizerError> {
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
            Err(self.error(TokenizerErrorKind::UnclosedData))
        } else {
            let mut raw_str = self.substring(start, self.cursor.position());
            raw_str = raw_str.replace(r#"\""#, "\"");
            raw_str = raw_str.replace(r#"\n"#, "\n");
            raw_str = raw_str.replace(r"\\", "\\");
            raw_str = raw_str.replace(r"\'", "'");
            raw_str = raw_str.replace(r"\r", "\r");
            raw_str = raw_str.replace(r"\t", "\t");
            self.cursor.advance();
            let span = self.cursor.span_from(start - 1);
            Ok(TokenKind::Literal(Literal::new(
                LiteralKind::Data(raw_str.as_bytes().to_vec()),
                span,
            )))
        }
    }

    fn parse_ipv4(
        &mut self,
        base: NumberBase,
        start: CharIndex,
    ) -> Result<TokenKind, TokenizerErrorKind> {
        use NumberBase::*;
        use TokenizerErrorKind::*;
        // IPv4Address start as Base10
        if base != Base10 {
            return Err(InvalidIpv4Address);
        }
        self.consume('.', InvalidIpv4Address)?;
        self.cursor
            .consume_while(base.verifier(), InvalidIpv4Address)?;
        self.consume('.', InvalidIpv4Address)?;
        self.cursor
            .consume_while(base.verifier(), InvalidIpv4Address)?;
        self.consume('.', InvalidIpv4Address)?;
        self.cursor
            .consume_while(base.verifier(), InvalidIpv4Address)?;
        let span = self.cursor.span_from(start);
        Ok(TokenKind::Literal(Literal::new(
            LiteralKind::IPv4Address(
                self.substring(start, self.cursor.position())
                    .parse()
                    .map_err(|_| InvalidIpv4Address)?,
            ),
            span,
        )))
    }

    fn tokenize_number(
        &mut self,
        mut start: CharIndex,
        current: char,
    ) -> Result<TokenKind, TokenizerError> {
        use NumberBase::*;
        let base = match (current, self.cursor.peek()) {
            ('0', 'b') => {
                // jump over non numeric
                self.cursor.advance();
                // we don't need `0b` later
                start += 2;
                Binary
            }
            ('0', 'x') => {
                // jump over non numeric
                self.cursor.advance();
                // we don't need `0x` later
                start += 2;
                Hex
            }
            ('0', c) if ('0'..='7').contains(&c) => {
                // we don't need leading 0 later
                start += 1;
                Octal
            }
            (_, c) => {
                if c.is_alphabetic() {
                    return Err(self.error(TokenizerErrorKind::InvalidNumberLiteral));
                } else {
                    Base10
                }
            }
        };
        self.cursor.skip_while(base.verifier());
        if self.cursor.peek() == '.' && self.cursor.peek_ahead(1).is_numeric() {
            self.parse_ipv4(base, start).map_err(|e| self.error(e))
        } else {
            // we verify that the cursor actually moved to prevent scenarios like
            // 0b without any actual number in it
            if start == self.cursor.position() {
                Err(self.error(TokenizerErrorKind::InvalidNumberLiteral))
            } else if self.cursor.peek().is_alphabetic() {
                self.cursor.advance();
                Err(self.error(TokenizerErrorKind::InvalidNumberLiteral))
            } else {
                let span = self.cursor.span_from(start);
                match i64::from_str_radix(
                    &self.substring(start, self.cursor.position()),
                    base.radix(),
                ) {
                    Ok(num) => Ok(TokenKind::Literal(Literal::new(
                        LiteralKind::Number(num),
                        span,
                    ))),
                    Err(_) => Err(self.error(TokenizerErrorKind::InvalidNumberLiteral)),
                }
            }
        }
    }

    fn tokenize_identifiers(&mut self, start: CharIndex) -> TokenKind {
        self.cursor
            .skip_while(|c| c.is_alphabetic() || c == '_' || c.is_numeric());
        let end = self.cursor.position();
        let lookup = self.substring(start, end);
        if lookup != "x" {
            if let Some(keyword) = Keyword::new(&lookup) {
                TokenKind::Keyword(keyword)
            } else if let Some(literal) = LiteralKind::from_keyword(&lookup) {
                TokenKind::Literal(Literal::new(literal, self.cursor.span_from(start)))
            } else {
                TokenKind::Ident(Ident::new(lookup, self.cursor.span_from(start)))
            }
        } else {
            self.cursor.skip_while(|c| c.is_whitespace());
            if self.cursor.peek().is_numeric() {
                TokenKind::X
            } else {
                TokenKind::Ident(Ident::new(lookup, self.cursor.span_from(start)))
            }
        }
    }
}

#[cfg(test)]
impl Iterator for Tokenizer {
    type Item = Result<Token, TokenizerError>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.advance()).filter(|token| {
            !matches!(
                token,
                Ok(Token {
                    kind: TokenKind::Eof,
                    ..
                }),
            )
        })
    }
}
