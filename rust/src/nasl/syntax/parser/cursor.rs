use crate::nasl::syntax::{Token, Tokenizer, TokenizerError, tokenizer::CharIndex};

use super::error::SpannedError;

pub trait Peek {
    fn peek(&self) -> &Token;
    fn peek_next(&self) -> &Token;
}

pub struct Cursor {
    tokenizer: Tokenizer,
    previous: Option<Token>,
    current: Token,
    next: Token,
    errors: Vec<TokenizerError>,
}

fn next_token(tokenizer: &mut Tokenizer, errors: &mut Vec<TokenizerError>) -> Token {
    loop {
        let result = tokenizer.advance();
        match result {
            Ok(token) => return token,
            Err(err) => errors.push(err),
        }
    }
}

impl Peek for Cursor {
    fn peek_next(&self) -> &Token {
        &self.next
    }

    fn peek(&self) -> &Token {
        &self.current
    }
}

impl Cursor {
    pub(crate) fn new(mut tokenizer: Tokenizer) -> Result<Self, SpannedError> {
        let mut errors = vec![];
        let current = next_token(&mut tokenizer, &mut errors);
        let next = next_token(&mut tokenizer, &mut errors);
        Ok(Self {
            tokenizer,
            previous: None,
            current,
            next,
            errors,
        })
    }

    pub fn advance(&mut self) -> Token {
        // TODO: If necessary, this can be sped up by
        // mem swapping.
        self.previous = Some(self.current.clone());
        self.current = self.next.clone();
        self.next = next_token(&mut self.tokenizer, &mut self.errors);
        self.current.clone()
    }

    pub(crate) fn current_token_start(&self) -> CharIndex {
        CharIndex(self.peek().position.0)
    }

    pub(crate) fn current_token_end(&self) -> CharIndex {
        CharIndex(
            self.previous
                .clone()
                .map(|prev| prev.position.1)
                .unwrap_or(0),
        )
    }

    pub(crate) fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub(crate) fn drain_errors(&mut self) -> impl Iterator<Item = TokenizerError> {
        self.errors.drain(..)
    }
}
