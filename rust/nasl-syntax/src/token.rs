use std::ops::Range;

///! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use crate::cursor::Cursor;

/// Identifies if a string is quoteable or unquoteable
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringCategory {
    Quoteable,   // '..\''
    Unquoteable, // "..\"
}

/// Identifies if number is base10, base 8, hex or binary
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Base {
    Binary, // 0b010101
    Octal,  // 0123456780
    Base10, // 1234567890
    Hex,    //0x123456789ABCDEF0
}

/// Is used to identify a Token
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    // Single-character tokens.
    LeftParen,         // (
    RightParen,        // )
    LeftBrace,         // [
    RightBrace,        // ]
    LeftCurlyBracket,  // {
    RightCurlyBracket, // }
    Comma,             // ,
    Dot,               // .
    Percent,           // %
    Semicolon,         // ;
    DoublePoint,       // :
    Tilde,             // ~
    Caret,             // ^
    // One or two character tokens
    Ampersand,          // &
    AmpersandAmpersand, // &&
    Pipe,               // |
    PipePipe,           // ||
    Bang,               // !
    BangEqual,          // !=
    BangTilde,          // !~
    Equal,              // =
    EqualEqual,         // ==
    EqualTilde,         // =~
    Greater,            // >
    GreaterGreater,     // >>
    GreaterEqual,       // >=
    GreaterLess,        // ><
    Less,               // <
    LessLess,           // <<
    LessEqual,          // <=
    Minus,              // -
    MinusMinus,         // --
    MinusEqual,         // -=
    Plus,               // +
    PlusEqual,          // +=
    PlusPlus,           // ++
    Slash,              // /
    SlashEqual,         // /=
    Star,               // *
    StarStar,           // **
    StarEqual,          // *=
    // Triple tokens
    GreaterGreaterGreater, // >>>
    GreaterGreaterEqual,   // >>=
    LessLessEqual,         // <<=
    LessLessLess,          // <<<
    GreaterBangLess,       // >!<
    // Tuple Tokens
    GreaterGreaterGreaterEqual, // >>>=
    LessLessLessEqual,          // <<<=
    // Variable size
    String(StringCategory), // "...\", multiline
    UnclosedString(StringCategory),
    Number(Base),
    UnknownSymbol, // used when the symbol is unknown
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Contains the TokenType as well as the position in form of Range<usize>
pub struct Token {
    category: Category,
    // using a tuple in favor of Range to have the possibility
    // to easily copy tokens rather than clone; to create a range for lookups
    // call range()
    position: (usize, usize),
}

impl Token {
    /// Returns the Category
    pub fn category(&self) -> Category {
        self.category
    }

    /// Returns the byte Range within original input
    pub fn range(&self) -> Range<usize> {
        let (start, end) = self.position;
        Range { start, end }
    }
}

/// Tokenizer uses a cursor to create tokens
#[derive(Clone)]
pub struct Tokenizer<'a> {
    // Is used to lookup keywords
    code: &'a str,
    cursor: Cursor<'a>,
}

// Is used to build Some(Token{ ... }) to make the match case within Iterator for Tokenizer easier to read
macro_rules! single_token {
    ($category:expr, $start:expr, $end:expr) => {
        Some(Token {
            category: $category,
            position: ($start, $end),
        })
    };
}

impl<'a> Tokenizer<'a> {
    /// Creates a new Tokenizer
    pub fn new(code: &'a str) -> Self {
        Tokenizer {
            code,
            cursor: Cursor::new(code),
        }
    }

    pub fn lookup(&self, range: Range<usize>) -> &'a str {
        &self.code[range]
    }

    // we break out of the macro since > can be parsed to:
    // >>>
    // >>=
    // >>>=
    // >!<
    // most operators don't have triple or tuple variant
    fn tokenize_greater(&mut self) -> Option<Token> {
        use Category::*;
        let start = self.cursor.len_consumed() - 1;
        let next = self.cursor.peek(0);
        match next {
            '=' => {
                self.cursor.advance();
                single_token!(GreaterEqual, start, self.cursor.len_consumed())
            }
            '<' => {
                self.cursor.advance();
                single_token!(GreaterLess, start, self.cursor.len_consumed())
            }
            '>' => {
                self.cursor.advance();
                let next = self.cursor.peek(0);
                match next {
                    '>' => {
                        self.cursor.advance();
                        if self.cursor.peek(0) == '=' {
                            self.cursor.advance();
                            return single_token!(
                                GreaterGreaterGreaterEqual,
                                start,
                                self.cursor.len_consumed()
                            );
                        }

                        single_token!(GreaterGreaterGreater, start, self.cursor.len_consumed())
                    }
                    '=' => {
                        self.cursor.advance();
                        single_token!(GreaterGreaterEqual, start, self.cursor.len_consumed())
                    }
                    _ => single_token!(GreaterGreater, start, self.cursor.len_consumed()),
                }
            }
            '!' if self.cursor.peek(1) == '<' => {
                self.cursor.advance();
                self.cursor.advance();
                single_token!(GreaterBangLess, start, self.cursor.len_consumed())
            }
            _ => single_token!(Greater, start, self.cursor.len_consumed()),
        }
    }

    // we break out of the macro since < can be parsed to:
    // <<<
    // <<=
    // <<<=
    // most operators don't have triple or tuple variant
    fn tokenize_less(&mut self) -> Option<Token> {
        use Category::*;
        let start = self.cursor.len_consumed() - 1;
        let next = self.cursor.peek(0);
        match next {
            '=' => {
                self.cursor.advance();
                single_token!(LessEqual, start, self.cursor.len_consumed())
            }
            '<' => {
                self.cursor.advance();
                let next = self.cursor.peek(0);
                match next {
                    '<' => {
                        self.cursor.advance();
                        if self.cursor.peek(0) == '=' {
                            self.cursor.advance();
                            return single_token!(
                                LessLessLessEqual,
                                start,
                                self.cursor.len_consumed()
                            );
                        }

                        single_token!(LessLessLess, start, self.cursor.len_consumed())
                    }
                    '=' => {
                        self.cursor.advance();
                        single_token!(LessLessEqual, start, self.cursor.len_consumed())
                    }
                    _ => single_token!(LessLess, start, self.cursor.len_consumed()),
                }
            }
            _ => single_token!(Less, start, self.cursor.len_consumed()),
        }
    }
}

// Is used to simplify cases for double_tokens, instead of having to rewrite each match case for each double_token
// this macro can be used:
//'+' => double_token!(self.cursor, start, '+', '+', PlusPlus, '=', PlusEqual),
// within the Iterator implementation of Tokenizer
macro_rules! double_token {
    ($cursor:expr, $start:tt, $c:tt, $($l:tt, $bt:expr ), *) => {
        {
            // enforce start to be usize
            let next = $cursor.peek(0);
            match next {
                $($l => {
                  $cursor.advance();
                  single_token!($bt, $start, $cursor.len_consumed())
                }, )*
                _ => single_token!($c, $start, $cursor.len_consumed()),
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
        match self.cursor.advance()? {
            '(' => single_token!(LeftParen, start, self.cursor.len_consumed()),
            ')' => single_token!(RightParen, start, self.cursor.len_consumed()),
            '[' => single_token!(LeftBrace, start, self.cursor.len_consumed()),
            ']' => single_token!(RightBrace, start, self.cursor.len_consumed()),
            '{' => single_token!(LeftCurlyBracket, start, self.cursor.len_consumed()),
            '}' => single_token!(RightCurlyBracket, start, self.cursor.len_consumed()),
            ',' => single_token!(Comma, start, self.cursor.len_consumed()),
            '.' => single_token!(Dot, start, self.cursor.len_consumed()),
            '-' => double_token!(self.cursor, start, Minus, '-', MinusMinus, '=', MinusEqual),
            '+' => double_token!(self.cursor, start, Plus, '+', PlusPlus, '=', PlusEqual),
            '%' => single_token!(Percent, start, self.cursor.len_consumed()),
            ';' => single_token!(Semicolon, start, self.cursor.len_consumed()),
            '/' => double_token!(self.cursor, start, Slash, '=', SlashEqual),
            '*' => double_token!(self.cursor, start, Star, '*', StarStar, '=', StarEqual),
            ':' => single_token!(DoublePoint, start, self.cursor.len_consumed()),
            '~' => single_token!(Tilde, start, self.cursor.len_consumed()),
            '&' => double_token!(self.cursor, start, Ampersand, '&', AmpersandAmpersand),
            '|' => double_token!(self.cursor, start, Pipe, '|', PipePipe),
            '^' => single_token!(Caret, start, self.cursor.len_consumed()),
            '!' => double_token!(self.cursor, start, Bang, '=', BangEqual, '~', BangTilde),
            '=' => double_token!(self.cursor, start, Equal, '=', EqualEqual, '~', EqualTilde),
            '>' => self.tokenize_greater(),
            '<' => self.tokenize_less(),
            '"' => {
                // we don't want the lookup to contain "
                let start = self.cursor.len_consumed();
                // we neither care about newlines nor escape character
                self.cursor.skip_while(|c| c != '"');
                if self.cursor.is_eof() {
                    single_token!(
                        UnclosedString(StringCategory::Unquoteable),
                        start,
                        self.cursor.len_consumed()
                    )
                } else {
                    let result = single_token!(
                        String(StringCategory::Unquoteable),
                        start,
                        self.cursor.len_consumed()
                    );
                    // skip "
                    self.cursor.advance();
                    result
                }
            }
            _ => single_token!(UnknownSymbol, start, self.cursor.len_consumed()),
        }
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
            let expected: Vec<Token> = $expected.iter().map(|x| build_token(*x)).collect();
            assert_eq!(actual, expected);
            (tokenizer, actual)
        }};
    }

    #[test]
    fn skip_white_space() {
        verify_tokens!("     (       ", vec![(Category::LeftParen, 5, 6)]);
    }

    #[test]
    fn single_token() {
        verify_tokens!("(", vec![(Category::LeftParen, 0, 1)]);
        verify_tokens!(")", vec![(Category::RightParen, 0, 1)]);
        verify_tokens!("[", vec![(Category::LeftBrace, 0, 1)]);
        verify_tokens!("]", vec![(Category::RightBrace, 0, 1)]);
        verify_tokens!("{", vec![(Category::LeftCurlyBracket, 0, 1)]);
        verify_tokens!("}", vec![(Category::RightCurlyBracket, 0, 1)]);
        verify_tokens!(",", vec![(Category::Comma, 0, 1)]);
        verify_tokens!(".", vec![(Category::Dot, 0, 1)]);
        verify_tokens!("-", vec![(Category::Minus, 0, 1)]);
        verify_tokens!("+", vec![(Category::Plus, 0, 1)]);
        verify_tokens!("%", vec![(Category::Percent, 0, 1)]);
        verify_tokens!(";", vec![(Category::Semicolon, 0, 1)]);
        verify_tokens!("/", vec![(Category::Slash, 0, 1)]);
        verify_tokens!("*", vec![(Category::Star, 0, 1)]);
        verify_tokens!(":", vec![(Category::DoublePoint, 0, 1)]);
        verify_tokens!("~", vec![(Category::Tilde, 0, 1)]);
        verify_tokens!("&", vec![(Category::Ampersand, 0, 1)]);
        verify_tokens!("|", vec![(Category::Pipe, 0, 1)]);
        verify_tokens!("^", vec![(Category::Caret, 0, 1)]);
    }

    #[test]
    fn double_token() {
        verify_tokens!("&", vec![(Category::Ampersand, 0, 1)]);
        verify_tokens!("&&", vec![(Category::AmpersandAmpersand, 0, 2)]);
        verify_tokens!("|", vec![(Category::Pipe, 0, 1)]);
        verify_tokens!("||", vec![(Category::PipePipe, 0, 2)]);
        verify_tokens!("!", vec![(Category::Bang, 0, 1)]);
        verify_tokens!("!=", vec![(Category::BangEqual, 0, 2)]);
        verify_tokens!("!~", vec![(Category::BangTilde, 0, 2)]);
        verify_tokens!("=", vec![(Category::Equal, 0, 1)]);
        verify_tokens!("==", vec![(Category::EqualEqual, 0, 2)]);
        verify_tokens!("=~", vec![(Category::EqualTilde, 0, 2)]);
        verify_tokens!(">", vec![(Category::Greater, 0, 1)]);
        verify_tokens!(">>", vec![(Category::GreaterGreater, 0, 2)]);
        verify_tokens!(">=", vec![(Category::GreaterEqual, 0, 2)]);
        verify_tokens!("><", vec![(Category::GreaterLess, 0, 2)]);
        verify_tokens!("<", vec![(Category::Less, 0, 1)]);
        verify_tokens!("<<", vec![(Category::LessLess, 0, 2)]);
        verify_tokens!("<=", vec![(Category::LessEqual, 0, 2)]);
        verify_tokens!("-", vec![(Category::Minus, 0, 1)]);
        verify_tokens!("--", vec![(Category::MinusMinus, 0, 2)]);
        verify_tokens!("+", vec![(Category::Plus, 0, 1)]);
        verify_tokens!("+=", vec![(Category::PlusEqual, 0, 2)]);
        verify_tokens!("++", vec![(Category::PlusPlus, 0, 2)]);
        verify_tokens!("/", vec![(Category::Slash, 0, 1)]);
        verify_tokens!("/=", vec![(Category::SlashEqual, 0, 2)]);
        verify_tokens!("*", vec![(Category::Star, 0, 1)]);
        verify_tokens!("**", vec![(Category::StarStar, 0, 2)]);
        verify_tokens!("*=", vec![(Category::StarEqual, 0, 2)]);
    }

    #[test]
    fn triple_tokens() {
        verify_tokens!(">>>", vec![(Category::GreaterGreaterGreater, 0, 3)]);
        verify_tokens!(">>=", vec![(Category::GreaterGreaterEqual, 0, 3)]);
        verify_tokens!(">!<", vec![(Category::GreaterBangLess, 0, 3)]);
        verify_tokens!("<<=", vec![(Category::LessLessEqual, 0, 3)]);
        verify_tokens!("<<<", vec![(Category::LessLessLess, 0, 3)]);
    }

    #[test]
    fn four_tuple_tokens() {
        verify_tokens!("<<<=", vec![(Category::LessLessLessEqual, 0, 4)]);
        verify_tokens!(">>>=", vec![(Category::GreaterGreaterGreaterEqual, 0, 4)]);
    }

    #[test]
    fn unquoteable_string() {
        use StringCategory::*;
        let code = "\"hello I am a closed string\\\"";
        let (tokenizer, result) =
            verify_tokens!(code, vec![(Category::String(Unquoteable), 1, 28)]);
        assert_eq!(
            tokenizer.lookup(result[0].range()),
            "hello I am a closed string\\"
        );
        let code = "\"hello I am a closed string\\";
        verify_tokens!(code, vec![(Category::UnclosedString(Unquoteable), 1, 28)]);
    }
}
