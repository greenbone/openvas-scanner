use std::fmt::Display;
use std::ops::Range;

use crate::ACT;

///! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use crate::cursor::Cursor;

/// Identifies if a string is quotable or unquotable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringCategory {
    /// Defines a string as capable of quoting
    ///
    /// Quotable strings will interpret \n\t...
    Quotable, // '..\''
    /// Defines a string as incapable of quoting
    ///
    /// Unquotable strings will use escaped characters as is instead of interpreting them.
    Unquotable, // "..\"
}

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
        ('0'..='9').contains(&peeked)
    }

    fn verify_hex(peeked: char) -> bool {
        ('0'..='9').contains(&peeked)
            || ('A'..='F').contains(&peeked)
            || ('a'..='f').contains(&peeked)
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
    String(StringCategory),
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

}

impl ToString for IdentifierType {
    fn to_string(&self) -> String {
        $(
        // special case that is not defined via macro_call
        if let IdentifierType::Undefined(r) = self {
            return r.clone();
        }
        // cannot use match here because define is an expression
        if self == &$define {
            return stringify!($matcher).to_owned();
        }
        )*
        return "".to_owned();
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
    /// A String can be either Quotable (') or Unquotable (") both can be multiline
    String(String),
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
            Category::LeftParen => write!(f, "LeftParen"),
            Category::RightParen => write!(f, "RightParen"),
            Category::LeftBrace => write!(f, "LeftBrace"),
            Category::RightBrace => write!(f, "RightBrace"),
            Category::LeftCurlyBracket => write!(f, "LeftCurlyBracket"),
            Category::RightCurlyBracket => write!(f, "RightCurlyBracket"),
            Category::Comma => write!(f, "Comma"),
            Category::Dot => write!(f, "Dot"),
            Category::Percent => write!(f, "Percent"),
            Category::PercentEqual => write!(f, "PercentEqual"),
            Category::Semicolon => write!(f, "Semicolon"),
            Category::DoublePoint => write!(f, "DoublePoint"),
            Category::Tilde => write!(f, "Tilde"),
            Category::Caret => write!(f, "Caret"),
            Category::Ampersand => write!(f, "Ampersand"),
            Category::AmpersandAmpersand => write!(f, "AmpersandAmpersand"),
            Category::Pipe => write!(f, "Pipe"),
            Category::PipePipe => write!(f, "PipePipe"),
            Category::Bang => write!(f, "Bang"),
            Category::BangEqual => write!(f, "BangEqual"),
            Category::BangTilde => write!(f, "BangTilde"),
            Category::Equal => write!(f, "Equal"),
            Category::EqualEqual => write!(f, "EqualEqual"),
            Category::EqualTilde => write!(f, "EqualTilde"),
            Category::Greater => write!(f, "Greater"),
            Category::GreaterGreater => write!(f, "GreaterGreater"),
            Category::GreaterEqual => write!(f, "GreaterEqual"),
            Category::GreaterLess => write!(f, "GreaterLess"),
            Category::Less => write!(f, "Less"),
            Category::LessLess => write!(f, "LessLess"),
            Category::LessEqual => write!(f, "LessEqual"),
            Category::Minus => write!(f, "Minus"),
            Category::MinusMinus => write!(f, "MinusMinus"),
            Category::MinusEqual => write!(f, "MinusEqual"),
            Category::Plus => write!(f, "Plus"),
            Category::PlusEqual => write!(f, "PlusEqual"),
            Category::PlusPlus => write!(f, "PlusPlus"),
            Category::Slash => write!(f, "Slash"),
            Category::SlashEqual => write!(f, "SlashEqual"),
            Category::Star => write!(f, "Star"),
            Category::StarStar => write!(f, "StarStar"),
            Category::StarEqual => write!(f, "StarEqual"),
            Category::GreaterGreaterGreater => write!(f, "GreaterGreaterGreater"),
            Category::GreaterGreaterEqual => write!(f, "GreaterGreaterEqual"),
            Category::LessLessEqual => write!(f, "LessLessEqual"),
            Category::GreaterBangLess => write!(f, "GreaterBangLess"),
            Category::GreaterGreaterGreaterEqual => write!(f, "GreaterGreaterGreaterEqual"),
            Category::X => write!(f, "X"),
            Category::String(_) => write!(f, "String"),
            Category::Number(_) => write!(f, "Number"),
            Category::IPv4Address(_) => write!(f, "IPv4Address"),
            Category::IllegalIPv4Address => write!(f, "IllegalIPv4Address"),
            Category::IllegalNumber(_) => write!(f, "IllegalNumber"),
            Category::Comment => write!(f, "Comment"),
            Category::Identifier(_) => write!(f, "Identifier"),
            Category::Unclosed(_) => write!(f, "Unclosed"),
            Category::UnknownBase => write!(f, "UnknownBase"),
            Category::UnknownSymbol => write!(f, "UnknownSymbol"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Contains the TokenType as well as the position in form of Range<usize>
pub struct Token {
    /// The category or kind of a token
    pub category: Category,
    /// The line and the column of the start of the token
    pub position: (usize, usize),
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
    #[inline(always)]
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
    #[inline(always)]
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

    // Skips initial and ending string identifier ' || " and verifies that a string is closed
    #[inline(always)]
    fn tokenize_string(
        &mut self,
        string_category: StringCategory,
        predicate: impl FnMut(char) -> bool,
    ) -> Category {
        // we don't want the lookup to contain "
        let start = self.cursor.len_consumed();
        self.cursor.skip_while(predicate);
        if self.cursor.is_eof() {
            Category::Unclosed(UnclosedCategory::String(string_category))
        } else {
            let result = {
                let raw = &self.code[Range {
                    start,
                    end: self.cursor.len_consumed(),
                }];
                match string_category {
                    StringCategory::Quotable => raw.to_owned(),
                    StringCategory::Unquotable => {
                        let mut string = raw.to_string();
                        string = string.replace(r#"\n"#, "\n");
                        string = string.replace(r#"\\"#, "\\");
                        string = string.replace(r#"\""#, "\"");
                        string = string.replace(r#"\'"#, "'");
                        string = string.replace(r#"\r"#, "\r");
                        string = string.replace(r#"\t"#, "\t");
                        string
                    }
                }
            };
            // skip ""
            self.cursor.advance();
            Category::String(result)
        }
    }
    #[inline(always)]
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
    #[inline(always)]
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
    #[inline(always)]
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
        let position = self.cursor.line_colum();
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
            '"' => self.tokenize_string(StringCategory::Unquotable, |c| c != '"'),
            '\'' => {
                let mut back_slash = false;
                self.tokenize_string(StringCategory::Quotable, |c| {
                    if !back_slash && c == '\'' {
                        false
                    } else {
                        back_slash = !back_slash && c == '\\';
                        true
                    }
                })
            }

            current if ('0'..='9').contains(&current) => self.tokenize_number(start, current),
            current if current.is_alphabetic() || current == '_' => self.tokenize_identifier(start),
            _ => UnknownSymbol,
        };
        Some(Token { category, position })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_token(input: (Category, usize, usize)) -> Token {
        let (category, start, end) = input;
        Token {
            category,
            position: (start, end),
        }
    }

    // use macro instead of a method to have correct line numbers on failure
    macro_rules! verify_tokens {
        ($code:expr, $expected:expr) => {{
            let tokenizer = Tokenizer::new($code);
            let actual: Vec<Token> = tokenizer.clone().collect();
            let expected: Vec<Token> = $expected.iter().map(|x| build_token(x.clone())).collect();
            assert_eq!(actual, expected);
            (tokenizer, actual)
        }};
    }

    #[test]
    fn skip_white_space() {
        verify_tokens!("     (       ", vec![(Category::LeftParen, 1, 6)]);
    }

    #[test]
    fn single_symbol_tokens() {
        verify_tokens!("(", vec![(Category::LeftParen, 1, 1)]);
        verify_tokens!(")", vec![(Category::RightParen, 1, 1)]);
        verify_tokens!("[", vec![(Category::LeftBrace, 1, 1)]);
        verify_tokens!("]", vec![(Category::RightBrace, 1, 1)]);
        verify_tokens!("{", vec![(Category::LeftCurlyBracket, 1, 1)]);
        verify_tokens!("}", vec![(Category::RightCurlyBracket, 1, 1)]);
        verify_tokens!(",", vec![(Category::Comma, 1, 1)]);
        verify_tokens!(".", vec![(Category::Dot, 1, 1)]);
        verify_tokens!("-", vec![(Category::Minus, 1, 1)]);
        verify_tokens!("+", vec![(Category::Plus, 1, 1)]);
        verify_tokens!("%", vec![(Category::Percent, 1, 1)]);
        verify_tokens!(";", vec![(Category::Semicolon, 1, 1)]);
        verify_tokens!("/", vec![(Category::Slash, 1, 1)]);
        verify_tokens!("*", vec![(Category::Star, 1, 1)]);
        verify_tokens!(":", vec![(Category::DoublePoint, 1, 1)]);
        verify_tokens!("~", vec![(Category::Tilde, 1, 1)]);
        verify_tokens!("&", vec![(Category::Ampersand, 1, 1)]);
        verify_tokens!("|", vec![(Category::Pipe, 1, 1)]);
        verify_tokens!("^", vec![(Category::Caret, 1, 1)]);
    }

    #[test]
    fn two_symbol_tokens() {
        verify_tokens!("&", vec![(Category::Ampersand, 1, 1)]);
        verify_tokens!("&&", vec![(Category::AmpersandAmpersand, 1, 1)]);
        verify_tokens!("|", vec![(Category::Pipe, 1, 1)]);
        verify_tokens!("||", vec![(Category::PipePipe, 1, 1)]);
        verify_tokens!("!", vec![(Category::Bang, 1, 1)]);
        verify_tokens!("!=", vec![(Category::BangEqual, 1, 1)]);
        verify_tokens!("!~", vec![(Category::BangTilde, 1, 1)]);
        verify_tokens!("=", vec![(Category::Equal, 1, 1)]);
        verify_tokens!("==", vec![(Category::EqualEqual, 1, 1)]);
        verify_tokens!("=~", vec![(Category::EqualTilde, 1, 1)]);
        verify_tokens!(">", vec![(Category::Greater, 1, 1)]);
        verify_tokens!(">>", vec![(Category::GreaterGreater, 1, 1)]);
        verify_tokens!(">=", vec![(Category::GreaterEqual, 1, 1)]);
        verify_tokens!("><", vec![(Category::GreaterLess, 1, 1)]);
        verify_tokens!("<", vec![(Category::Less, 1, 1)]);
        verify_tokens!("<<", vec![(Category::LessLess, 1, 1)]);
        verify_tokens!("<=", vec![(Category::LessEqual, 1, 1)]);
        verify_tokens!("-", vec![(Category::Minus, 1, 1)]);
        verify_tokens!("--", vec![(Category::MinusMinus, 1, 1)]);
        verify_tokens!("+", vec![(Category::Plus, 1, 1)]);
        verify_tokens!("+=", vec![(Category::PlusEqual, 1, 1)]);
        verify_tokens!("++", vec![(Category::PlusPlus, 1, 1)]);
        verify_tokens!("/", vec![(Category::Slash, 1, 1)]);
        verify_tokens!("/=", vec![(Category::SlashEqual, 1, 1)]);
        verify_tokens!("*", vec![(Category::Star, 1, 1)]);
        verify_tokens!("**", vec![(Category::StarStar, 1, 1)]);
        verify_tokens!("*=", vec![(Category::StarEqual, 1, 1)]);
    }

    #[test]
    fn three_symbol_tokens() {
        verify_tokens!(">>>", vec![(Category::GreaterGreaterGreater, 1, 1)]);
        verify_tokens!(">>=", vec![(Category::GreaterGreaterEqual, 1, 1)]);
        verify_tokens!(">!<", vec![(Category::GreaterBangLess, 1, 1)]);
        verify_tokens!("<<=", vec![(Category::LessLessEqual, 1, 1)]);
    }

    #[test]
    fn four_symbol_tokens() {
        verify_tokens!(">>>=", vec![(Category::GreaterGreaterGreaterEqual, 1, 1)]);
    }

    #[test]
    fn unquotable_string() {
        use StringCategory::*;
        let code = "\"hello I am a closed string\\\"";
        verify_tokens!(
            code,
            vec![(
                Category::String("hello I am a closed string\\".to_owned()),
                1,
                1,
            )]
        );
        let code = "\"hello I am a unclosed string\\";
        verify_tokens!(
            code,
            vec![(
                Category::Unclosed(UnclosedCategory::String(Unquotable)),
                1,
                1,
            )]
        );
    }

    #[test]
    fn quotable_string() {
        use StringCategory::*;
        let code = "'Hello \\'you\\'!'";
        verify_tokens!(
            code,
            vec![(Category::String("Hello \\'you\\'!".to_owned()), 1, 1)]
        );
        let code = "'Hello \\'you\\'!\\'";
        verify_tokens!(
            code,
            vec![(Category::Unclosed(UnclosedCategory::String(Quotable)), 1, 1)]
        );
    }

    #[test]
    fn numbers() {
        use Base::*;
        use Category::*;
        verify_tokens!("0", vec![(Number(0), 1, 1)]);
        verify_tokens!("0b01", vec![(Number(1), 1, 1)]);
        verify_tokens!("1234567890", vec![(Number(1234567890), 1, 1)]);
        // TODO remove float
        //verify_tokens!("0.123456789", vec![(Number(Base10), 1, 1)]);
        verify_tokens!("012345670", vec![(Number(2739128), 1, 1)]);
        verify_tokens!(
            "0x1234567890ABCDEF",
            vec![(Number(1311768467294899695), 1, 1)]
        );
        // That would be later illegal because a number if followed by a number
        // but within tokenizing I think it is the best to ignore that and let it be handled by AST
        verify_tokens!("0b02", vec![(Number(0), 1, 1), (Number(2), 1, 4)]);
        verify_tokens!(
            "0b2",
            vec![(IllegalNumber(Binary), 1, 1), (Number(2), 1, 3)]
        );
    }

    #[test]
    fn single_line_comments() {
        use Category::*;
        verify_tokens!(
            "# this is a comment\n;",
            vec![(Comment, 1, 1), (Semicolon, 2, 1)]
        );
    }

    #[test]
    fn identifier() {
        use Category::*;
        use IdentifierType::*;
        verify_tokens!(
            "hel_lo",
            vec![(Identifier(Undefined("hel_lo".to_owned())), 1, 1)]
        );
        verify_tokens!(
            "_hello",
            vec![(Identifier(Undefined("_hello".to_owned())), 1, 1)]
        );
        verify_tokens!(
            "_h4llo",
            vec![(Identifier(Undefined("_h4llo".to_owned())), 1, 1)]
        );
        verify_tokens!(
            "4_h4llo",
            vec![
                (Number(4), 1, 1),
                (Identifier(Undefined("_h4llo".to_owned())), 1, 2)
            ]
        );
    }

    #[test]
    fn keywords() {
        use Category::*;
        use IdentifierType::*;
        verify_tokens!("for", vec![(Identifier(For), 1, 1)]);
        verify_tokens!("foreach", vec![(Identifier(ForEach), 1, 1)]);
        verify_tokens!("if", vec![(Identifier(If), 1, 1)]);
        verify_tokens!("else", vec![(Identifier(Else), 1, 1)]);
        verify_tokens!("while", vec![(Identifier(While), 1, 1)]);
        verify_tokens!("repeat", vec![(Identifier(Repeat), 1, 1)]);
        verify_tokens!("until", vec![(Identifier(Until), 1, 1)]);
        verify_tokens!("local_var", vec![(Identifier(LocalVar), 1, 1)]);
        verify_tokens!("global_var", vec![(Identifier(GlobalVar), 1, 1)]);
        verify_tokens!("NULL", vec![(Identifier(Null), 1, 1)]);
        verify_tokens!("return", vec![(Identifier(Return), 1, 1)]);
        verify_tokens!("include", vec![(Identifier(Include), 1, 1)]);
        verify_tokens!("exit", vec![(Identifier(Exit), 1, 1)]);
        verify_tokens!("break", vec![(Identifier(Break), 1, 1)]);
        verify_tokens!("continue", vec![(Identifier(Continue), 1, 1)]);
    }

    #[test]
    fn string_quoting() {
        use Category::*;
        verify_tokens!(
            r###"'webapps\\appliance\\'"###,
            vec![(String("webapps\\\\appliance\\\\".to_owned()), 1, 1)]
        );
    }

    #[test]
    fn simplified_ipv4_address() {
        use Category::*;
        verify_tokens!("10.187.76.12", vec![(IPv4Address("10.187.76.12".to_owned()), 1, 1)]);
    }

    #[test]
    fn repeat_x_times() {
        use Category::*;
        verify_tokens!(
            "x() x 10;",
            vec![
                (Identifier(IdentifierType::Undefined("x".to_owned())), 1, 1),
                (LeftParen, 1, 2),
                (RightParen, 1, 3),
                (X, 1, 5),
                (Number(10), 1, 7),
                (Semicolon, 1, 9),
            ]
        );
    }

    #[test]
    fn tokenize_description_block() {
        use Category::*;
        use IdentifierType::*;

        let code = r#"
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.99999");
  exit(0);
}

j = 123;
j >>>= 8;
display(j);
exit(1);
"#;
        verify_tokens!(
            code,
            vec![
                (Identifier(If), 2, 1),
                (LeftParen, 2, 3), // start expression block
                (Identifier(Undefined("description".to_owned())), 2, 4), // verify is description is true
                (RightParen, 2, 15),                                     // end expression block
                (LeftCurlyBracket, 3, 1),                                // start execution block
                (Identifier(Undefined("script_oid".to_owned())), 4, 3), // lookup function script_oid
                (LeftParen, 4, 13), // start parameter expression block
                (String("1.3.6.1.4.1.25623.1.0.99999".to_owned()), 4, 14), // resolve prime to "1.3.6.1.4.1.25623.1.0.99999"
                (RightParen, 4, 43),                                       // end expression block
                (Semicolon, 4, 44),                                        // finish execution
                (Identifier(Exit), 5, 3),                                  // lookup keyword exit
                (LeftParen, 5, 7),         // start parameter expression block
                (Number(0), 5, 8),         // call exit with 0
                (RightParen, 5, 9),        // end expression block
                (Semicolon, 5, 10),        // finish execution
                (RightCurlyBracket, 6, 1), // finish expression block
                (Identifier(Undefined("j".to_owned())), 8, 1), // lookup j
                (Equal, 8, 3),             // assign to j
                (Number(123), 8, 5),       // number 123
                (Semicolon, 8, 8),         // finish execution
                (Identifier(Undefined("j".to_owned())), 9, 1), // lookup j
                (GreaterGreaterGreaterEqual, 9, 3), // shift j and assign to j
                (Number(8), 9, 8),         // 8
                (Semicolon, 9, 9),         // finish execution
                (Identifier(Undefined("display".to_owned())), 10, 1), // lookup display
                (LeftParen, 10, 8),        // start parameter expression block
                (Identifier(Undefined("j".to_owned())), 10, 9), // resolve j primitive
                (RightParen, 10, 10),      // finish parameter expression block
                (Semicolon, 10, 11),       // finish execution
                (Identifier(Exit), 11, 1), // lookup keyword exit
                (LeftParen, 11, 5),        // start parameter expression block
                (Number(1), 11, 6),        // call exit with 1
                (RightParen, 11, 7),       // finish parameter expression block
                (Semicolon, 11, 8)         // finish execution
            ]
        );
    }
}
