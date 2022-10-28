use std::ops::Range;

///! This module defines the TokenTypes as well as Token and extends Cursor with advance_token
use crate::cursor::Cursor;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd)]
/// Is used to identify a Token
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
pub struct Tokenizer<'a> {
    // Is used to lookup keywords
    //code: &'a str,
    cursor: Cursor<'a>,
}

impl<'a> Tokenizer<'a> {
    /// Creates a new Tokenizer
    pub fn new(code: &'a str) -> Self {
        Tokenizer {
            cursor: Cursor::new(code),
        }
    }
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
            '>' => double_token!(
                self.cursor,
                start,
                Greater,
                '=',
                GreaterEqual,
                '>',
                GreaterGreater,
                '<',
                GreaterLess
            ),
            '<' => double_token!(self.cursor, start, Less, '=', LessEqual, '<', LessLess),
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
        ($code:expr, $expected:expr) => {
            let actual: Vec<Token> = Tokenizer::new($code).collect();
            let expected: Vec<Token> = $expected.iter().map(|x| build_token(*x)).collect();
            assert_eq!(actual, expected);
        };
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
}
