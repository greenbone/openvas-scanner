use crate::nasl::syntax::{Token, TokenKind, Tokenizer, TokenizerError, tokenizer::CharIndex};

use super::{Matches, error::SpannedError};

pub trait Peek: Sized {
    fn peek(&self) -> &TokenKind;
    fn peek_next(&self) -> &TokenKind;

    fn lookahead(&self) -> Lookahead {
        Lookahead {
            current: &self.peek_next(),
        }
    }

    fn matches<T: Matches>(&self) -> bool {
        T::matches(self)
    }

    fn matches_next<T: Matches>(&self) -> bool {
        let lookahead = self.lookahead();
        lookahead.matches::<T>()
    }
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
    fn peek_next(&self) -> &TokenKind {
        &self.next.kind
    }

    fn peek(&self) -> &TokenKind {
        &self.current.kind
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
        CharIndex(self.current.position.0)
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

pub struct Lookahead<'a> {
    current: &'a TokenKind,
}

impl<'a> Peek for Lookahead<'a> {
    fn peek(&self) -> &TokenKind {
        self.current
    }

    fn peek_next(&self) -> &TokenKind {
        // We don't need this
        unimplemented!()
    }
}
