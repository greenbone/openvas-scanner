// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

//! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use std::fmt::Display;
use std::ops::Range;

use crate::ACT;

use crate::cursor::Cursor;

/// Identifies if number is base10, base 8, hex or binary
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    /// Base 2: contains 01 is defined by 0b e.g.: `0b010101`
    Binary,
    /// Base 8: contains 0-8 is defined by a starting 0 e.g.: `0123456780`
    Octal,
    /// Base 10: contains 0-9 is the default e.g.: `1234567890`
    Base10,
    /// Base 16: contains 0-9A-F is defined by a starting 0x e.g.: `0x123456789ABCDEF0`
    Hex,
}

impl Base {
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
            Base::Binary => 2,
            Base::Octal => 8,
            Base::Base10 => 10,
            Base::Hex => 16,
        }
    }
}

/// Is used to identify which Category type is unclosed
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnclosedCategory {
    /// Is a unclosed String.
    String,
    Data,
}

macro_rules! make_keyword_matcher {
    ($($matcher:ident : $define:expr),+) => {

impl IdentifierType {
    /// Creates a new keyword based on a string identifier
    pub fn new(keyword: &str) -> Self {
        match keyword {
           $(
           stringify!($matcher) => $define,
           )*
            _ => Self::Undefined(keyword.to_owned())
        }

    }

    /// Returns the length of the identifier
    pub fn len(&self) -> usize {
        $(
        if self == &$define {
            return stringify!($matcher).len();
        }
        )*
        if let IdentifierType::Undefined(r) = self {
            return r.len();
        } else {
            return 0;
        }
    }

    /// Returns true when len == 0
    pub fn is_empty(&self) -> bool {
         self.len() == 0
    }

}
impl Display for IdentifierType {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        $(
        if self == &$define {
            return write!(f, stringify!($matcher));
        }
        )*
        if let IdentifierType::Undefined(r) = self {
            return write!(f, "{r}");
        } else {
            return Ok(());
        }
    }
}
    };
}

/// Unless Dynamic those are reserved words that cannot be reused otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentifierType {
    /// function declaration
    Function,
    /// _FCT_ANON_ARGS
    FCTAnonArgs,
    /// TRUE
    True,
    /// FALSE
    False,
    /// for
    For,
    /// foreach
    ForEach,
    /// if
    If,
    /// else
    Else,
    /// while
    While,
    /// repeat
    Repeat,
    /// until
    Until,
    /// local_var
    LocalVar,
    /// global_var
    GlobalVar,
    /// NULL
    Null,
    /// return
    Return,
    /// continue
    Continue,
    /// break
    Break,
    /// include
    Include,
    /// Scanning phases; can be set by category in the description block
    ACT(ACT),
    /// exit
    Exit,
    /// Undefined
    Undefined(String),
}

make_keyword_matcher! {
    function: IdentifierType::Function,
    _FCT_ANON_ARGS: IdentifierType::FCTAnonArgs,
    TRUE: IdentifierType::True,
    FALSE: IdentifierType::False,
    for: IdentifierType::For,
    foreach: IdentifierType::ForEach,
    if: IdentifierType::If,
    else: IdentifierType::Else,
    while: IdentifierType::While,
    repeat: IdentifierType::Repeat,
    until: IdentifierType::Until,
    local_var: IdentifierType::LocalVar,
    global_var: IdentifierType::GlobalVar,
    NULL: IdentifierType::Null,
    return: IdentifierType::Return,
    include: IdentifierType::Include,
    exit: IdentifierType::Exit,
    ACT_ATTACK: IdentifierType::ACT(ACT::Attack),
    ACT_DENIAL: IdentifierType::ACT(ACT::Denial),
    ACT_DESTRUCTIVE_ATTACK: IdentifierType::ACT(ACT::DestructiveAttack),
    ACT_END: IdentifierType::ACT(ACT::End),
    ACT_FLOOD: IdentifierType::ACT(ACT::Flood),
    ACT_GATHER_INFO: IdentifierType::ACT(ACT::GatherInfo),
    ACT_INIT: IdentifierType::ACT(ACT::Init),
    ACT_KILL_HOST: IdentifierType::ACT(ACT::KillHost),
    ACT_MIXED_ATTACK: IdentifierType::ACT(ACT::MixedAttack),
    ACT_SCANNER: IdentifierType::ACT(ACT::Scanner),
    ACT_SETTINGS: IdentifierType::ACT(ACT::Settings),
    continue: IdentifierType::Continue,
    break: IdentifierType::Break
}

/// Is used to identify a Token
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Category {
    /// `(`
    LeftParen,
    /// `)`
    RightParen,
    /// `[`
    LeftBrace,
    /// `]`
    RightBrace,
    /// `{`
    LeftCurlyBracket,
    /// `}`
    RightCurlyBracket,
    /// `,`
    Comma,
    /// `.`
    Dot,
    /// `%`
    Percent,
    /// `%=`
    PercentEqual,
    /// `;`
    Semicolon,
    /// `:`
    DoublePoint,
    /// `~`
    Tilde,
    /// `^`
    Caret,
    /// `&`
    Ampersand,
    /// `&&`
    AmpersandAmpersand,
    /// `|`
    Pipe,
    /// `||`
    PipePipe,
    /// `!`
    Bang,
    /// `!=`
    BangEqual,
    /// `!~`
    BangTilde,
    /// `=`
    Equal,
    /// `==`
    EqualEqual,
    /// `=~`
    EqualTilde,
    /// `>`
    Greater,
    /// `>>`
    GreaterGreater,
    /// `>=`
    GreaterEqual,
    /// `><`
    GreaterLess,
    /// `<`
    Less,
    /// `<<`
    LessLess,
    /// `<=`
    LessEqual,
    /// `-`
    Minus,
    /// `--`
    MinusMinus,
    /// `-=`
    MinusEqual,
    /// `+`
    Plus,
    /// `+=`
    PlusEqual,
    /// `++`
    PlusPlus,
    /// `/`
    Slash,
    /// `/=`
    SlashEqual,
    /// `*`
    Star,
    /// `**`
    StarStar,
    /// `*=`
    StarEqual,
    /// `>>>`
    GreaterGreaterGreater,
    /// `>>=`
    GreaterGreaterEqual,
    /// `<<=`
    LessLessEqual,
    /// `>!<`
    GreaterBangLess,
    /// `>>>=`
    GreaterGreaterGreaterEqual,
    /// `x` is a special functionality to redo a function call n times.E.g. `send_packet( udp, pcap_active:FALSE ) x 200;`
    X,
    /// A String (")
    ///
    /// Strings can be over multiple lines and are not escapable (`a = "a\";` is valid).
    /// A string type will be cast to utf8 string.
    String(String),
    /// Data is defined Quotable (')
    ///
    /// Data can be over multiple lines and are escaped (`a = "a\";` is valid).
    /// Unlike string the data types are stored in bytes.
    Data(Vec<u8>),
    /// A Number can be either binary (0b), octal (0), base10 (1-9) or hex (0x)
    Number(i64),
    /// We currently just support 127.0.0.1 notation
    IPv4Address(String),
    /// Wrongfully identified as IpV4
    IllegalIPv4Address,
    /// An illegal Number e.g. 0b2
    IllegalNumber(Base),
    /// A comment starts with # and should be ignored
    Comment,
    /// Identifier are literals that are not strings and don't start with a number
    Identifier(IdentifierType),
    /// Unclosed token. This can happen on e.g. string literals
    Unclosed(UnclosedCategory),
    /// Number starts with an unidentifiable base
    UnknownBase,
    /// used when the symbol is unknown
    UnknownSymbol,
}

impl Display for Category {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Category::LeftParen => write!(f, "("),
            Category::RightParen => write!(f, ")"),
            Category::LeftBrace => write!(f, "["),
            Category::RightBrace => write!(f, "]"),
            Category::LeftCurlyBracket => write!(f, "{{"),
            Category::RightCurlyBracket => write!(f, "}}"),
            Category::Comma => write!(f, ","),
            Category::Dot => write!(f, "."),
            Category::Percent => write!(f, "%"),
            Category::PercentEqual => write!(f, "%="),
            Category::Semicolon => write!(f, ";"),
            Category::DoublePoint => write!(f, ":"),
            Category::Tilde => write!(f, "~"),
            Category::Caret => write!(f, "^"),
            Category::Ampersand => write!(f, "&"),
            Category::AmpersandAmpersand => write!(f, "&&"),
            Category::Pipe => write!(f, "|"),
            Category::PipePipe => write!(f, "||"),
            Category::Bang => write!(f, "!"),
            Category::BangEqual => write!(f, "!="),
            Category::BangTilde => write!(f, "!~"),
            Category::Equal => write!(f, "="),
            Category::EqualEqual => write!(f, "=="),
            Category::EqualTilde => write!(f, "=~"),
            Category::Greater => write!(f, ">"),
            Category::GreaterGreater => write!(f, ">>"),
            Category::GreaterEqual => write!(f, ">="),
            Category::GreaterLess => write!(f, "><"),
            Category::Less => write!(f, "<"),
            Category::LessLess => write!(f, "<<"),
            Category::LessEqual => write!(f, "<="),
            Category::Minus => write!(f, "-"),
            Category::MinusMinus => write!(f, "--"),
            Category::MinusEqual => write!(f, "-="),
            Category::Plus => write!(f, "+"),
            Category::PlusEqual => write!(f, "+="),
            Category::PlusPlus => write!(f, "++"),
            Category::Slash => write!(f, "/"),
            Category::SlashEqual => write!(f, "/="),
            Category::Star => write!(f, "*"),
            Category::StarStar => write!(f, "**"),
            Category::StarEqual => write!(f, "*="),
            Category::GreaterGreaterGreater => write!(f, ">>>"),
            Category::GreaterGreaterEqual => write!(f, ">>="),
            Category::LessLessEqual => write!(f, "<<="),
            Category::GreaterBangLess => write!(f, ">!<"),
            Category::GreaterGreaterGreaterEqual => write!(f, ">>>="),
            Category::X => write!(f, "X"),
            Category::String(x) => write!(f, "\"{x}\""),
            Category::Number(x) => write!(f, "{x}"),
            Category::IPv4Address(x) => write!(f, "{x}"),
            Category::IllegalIPv4Address => write!(f, "IllegalIPv4Address"),
            Category::IllegalNumber(_) => write!(f, "IllegalNumber"),
            Category::Comment => write!(f, "Comment"),
            Category::Identifier(x) => write!(f, "{}", x),
            Category::Unclosed(x) => write!(f, "Unclosed{x:?}"),
            Category::UnknownBase => write!(f, "UnknownBase"),
            Category::UnknownSymbol => write!(f, "UnknownSymbol"),
            Category::Data(x) => write!(f, "{x:?}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the TokenType as well as the position.
pub struct Token {
    /// The category or kind of a token
    pub category: Category,
    /// The line and the column of the start of the token
    pub line_column: (usize, usize),
    /// Byte position
    pub position: (usize, usize),
}

impl Default for Token {
    fn default() -> Self {
        Token {
            category: Category::UnknownSymbol,
            line_column: (0, 0),
            position: (0, 0),
        }
    }
}

impl Token {
    /// Returns UnknownSymbol without line column or position
    pub fn unexpected_none() -> Self {
        Self {
            category: Category::UnknownSymbol,
            line_column: (0, 0),
            position: (0, 0),
        }
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} {}",
            self.line_column.0, self.line_column.1, self.category
        )
    }
}

impl Token {
    /// Returns the Category
    pub fn category(&self) -> &Category {
        &self.category
    }

    /// Returns true when an Token is faulty
    ///
    /// A Token is faulty when it is a syntactical error like
    /// - [Category::IllegalIPv4Address]
    /// - [Category::Unclosed]
    /// - [Category::UnknownBase]
    /// - [Category::UnknownSymbol]
    /// - [Category::IllegalNumber]
    pub fn is_faulty(&self) -> bool {
        matches!(
            self.category(),
            Category::IllegalIPv4Address
                | Category::IllegalNumber(_)
                | Category::Unclosed(_)
                | Category::UnknownBase
                | Category::UnknownSymbol
        )
    }
}

/// Tokenizer uses a cursor to create tokens
#[derive(Clone)]
pub struct Tokenizer<'a> {
    // Is used to lookup keywords
    code: &'a str,
    cursor: Cursor<'a>,
}

impl<'a> Tokenizer<'a> {
    /// Creates a new Tokenizer
    pub fn new(code: &'a str) -> Self {
        Tokenizer {
            code,
            cursor: Cursor::new(code),
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
    fn tokenize_greater(&mut self) -> Category {
        use Category::*;
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
    fn tokenize_less(&mut self) -> Category {
        use Category::*;
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
    fn tokenize_string(&mut self) -> Category {
        //'"' => self.tokenize_string(StringCategory::Unquotable, |c| c != '"'),
        let start = self.cursor.len_consumed();
        self.cursor.skip_while(|c| c != '"');
        if self.cursor.is_eof() {
            Category::Unclosed(UnclosedCategory::String)
        } else {
            let mut result = self.code[Range {
                start,
                end: self.cursor.len_consumed(),
            }]
            .to_owned();
            result = result.replace(r"\n", "\n");
            result = result.replace(r"\\", "\\");
            result = result.replace(r#"\""#, "\"");
            result = result.replace(r"\'", "'");
            result = result.replace(r"\r", "\r");
            result = result.replace(r"\t", "\t");
            // skip ""
            self.cursor.advance();
            Category::String(result)
        }
    }

    // Skips initial and ending string identifier ' || " and verifies that a string is closed
    fn tokenize_data(&mut self) -> Category {
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
            Category::Unclosed(UnclosedCategory::Data)
        } else {
            let mut raw_str = self.code[Range {
                start,
                end: self.cursor.len_consumed(),
            }]
            .to_owned();
            raw_str = raw_str.replace(r#"\""#, "\"");
            self.cursor.advance();
            Category::Data(raw_str.as_bytes().to_vec())
        }
    }
    fn may_parse_ipv4(&mut self, base: Base, start: usize) -> Option<Category> {
        use Base::*;
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
                    return Some(Category::IllegalIPv4Address);
                }

                if self.cursor.peek(0) == '.' && self.cursor.peek(1).is_numeric() {
                    self.cursor.advance();
                    self.cursor.skip_while(base.verifier());
                } else {
                    return Some(Category::IllegalIPv4Address);
                }
                return Some(Category::IPv4Address(
                    self.code[Range {
                        start,
                        end: self.cursor.len_consumed(),
                    }]
                    .to_owned(),
                ));
            } else {
                return Some(Category::IllegalIPv4Address);
            }
        }
        None
    }

    // checks if a number is binary, octal, base10 or hex
    fn tokenize_number(&mut self, mut start: usize, current: char) -> Category {
        use Base::*;
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
                        Category::IllegalNumber(base)
                    } else {
                        match i64::from_str_radix(
                            &self.code[Range {
                                start,
                                end: self.cursor.len_consumed(),
                            }],
                            base.radix(),
                        ) {
                            Ok(num) => Category::Number(num),
                            Err(_) => Category::IllegalNumber(base),
                        }
                    }
                }
            }
        } else {
            Category::UnknownBase
        }
    }

    // Checks if an identifier is a Keyword or not
    fn tokenize_identifier(&mut self, start: usize) -> Category {
        self.cursor
            .skip_while(|c| c.is_alphabetic() || c == '_' || c.is_numeric());
        let end = self.cursor.len_consumed();
        let lookup = self.lookup(Range { start, end });
        if lookup != "x" {
            let keyword = IdentifierType::new(lookup);
            Category::Identifier(keyword)
        } else {
            self.cursor.skip_while(|c| c.is_whitespace());
            if self.cursor.peek(0).is_numeric() {
                Category::X
            } else {
                Category::Identifier(IdentifierType::Undefined(lookup.to_owned()))
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

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        use Category::*;
        self.cursor.skip_while(|c| c.is_whitespace());
        let start = self.cursor.len_consumed();
        let position = self.cursor.line_column();
        let category: Category = match self.cursor.advance()? {
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
            '+' => two_symbol_token!(self.cursor, start, Plus, '+', PlusPlus, '=', PlusEqual),
            '%' => two_symbol_token!(self.cursor, start, Percent, '=', PercentEqual),
            ';' => Semicolon,
            '/' => two_symbol_token!(self.cursor, start, Slash, '=', SlashEqual), /* self.tokenize_slash(start), */
            '*' => two_symbol_token!(self.cursor, start, Star, '*', StarStar, '=', StarEqual),
            ':' => DoublePoint,
            '~' => Tilde,
            '&' => two_symbol_token!(self.cursor, start, Ampersand, '&', AmpersandAmpersand),
            '|' => two_symbol_token!(self.cursor, start, Pipe, '|', PipePipe),
            '^' => Caret,
            '!' => two_symbol_token!(self.cursor, start, Bang, '=', BangEqual, '~', BangTilde),
            '=' => two_symbol_token!(self.cursor, start, Equal, '=', EqualEqual, '~', EqualTilde),
            '>' => self.tokenize_greater(),
            '<' => self.tokenize_less(),
            '"' => self.tokenize_string(),
            '\'' => self.tokenize_data(),

            current if current.is_ascii_digit() => self.tokenize_number(start, current),
            current if current.is_alphabetic() || current == '_' => self.tokenize_identifier(start),
            _ => UnknownSymbol,
        };
        let byte_position = (start, self.cursor.len_consumed());
        Some(Token {
            category,
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
            let tokenizer = Tokenizer::new($code);
            let actual: Vec<String> = tokenizer.map(|t| t.category().to_string()).collect();
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
            "'Hello \\'you\\'!'",
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
        verify_tokens!("# this is a comment\n;", ["Comment", ";"]);
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
            r"'webapps\\appliance\\'",
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
