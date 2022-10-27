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
    Minus,             // -
    Plus,              // +
    Percent,           // %
    Semicolon,         // ;
    Slash,             // /
    Star,              // *
    DoublePoint,       // :
    Tilde,             // ~
    Ampersand,         // &
    Pipe,              // |
    Caret,             // ^

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
    pub fn new(code: &'a str) -> Self {
        Tokenizer {
            cursor: Cursor::new(code),
        }
    }
}

impl<'a> Iterator for Tokenizer<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        self.cursor.skip_while(|c| c.is_whitespace());
        let initial_pos = self.cursor.len_consumed();
        let build_token = |category, start, end| -> Option<Token> {
            Some(Token {
                category,
                position: (start, end),
            })
        };
        match self.cursor.advance()? {
            '(' => build_token(Category::LeftParen, initial_pos, self.cursor.len_consumed()),
            ')' => build_token(
                Category::RightParen,
                initial_pos,
                self.cursor.len_consumed(),
            ),
            '[' => build_token(Category::LeftBrace, initial_pos, self.cursor.len_consumed()),
            ']' => build_token(
                Category::RightBrace,
                initial_pos,
                self.cursor.len_consumed(),
            ),
            '{' => build_token(
                Category::LeftCurlyBracket,
                initial_pos,
                self.cursor.len_consumed(),
            ),
            '}' => build_token(
                Category::RightCurlyBracket,
                initial_pos,
                self.cursor.len_consumed(),
            ),
            ',' => build_token(Category::Comma, initial_pos, self.cursor.len_consumed()),
            '.' => build_token(Category::Dot, initial_pos, self.cursor.len_consumed()),
            '-' => build_token(Category::Minus, initial_pos, self.cursor.len_consumed()),
            '+' => build_token(Category::Plus, initial_pos, self.cursor.len_consumed()),
            '%' => build_token(Category::Percent, initial_pos, self.cursor.len_consumed()),
            ';' => build_token(Category::Semicolon, initial_pos, self.cursor.len_consumed()),
            '/' => build_token(Category::Slash, initial_pos, self.cursor.len_consumed()),
            '*' => build_token(Category::Star, initial_pos, self.cursor.len_consumed()),
            ':' => build_token(
                Category::DoublePoint,
                initial_pos,
                self.cursor.len_consumed(),
            ),
            '~' => build_token(Category::Tilde, initial_pos, self.cursor.len_consumed()),
            '&' => build_token(Category::Ampersand, initial_pos, self.cursor.len_consumed()),
            '|' => build_token(Category::Pipe, initial_pos, self.cursor.len_consumed()),
            '^' => build_token(Category::Caret, initial_pos, self.cursor.len_consumed()),
            _ => build_token(
                Category::UnknownSymbol,
                initial_pos,
                self.cursor.len_consumed(),
            ),
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
}
