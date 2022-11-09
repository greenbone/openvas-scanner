use crate::token::{Category, Keyword, Token};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Operator(Category),
    Assign(Category),
    Grouping(Category), // grouping operator ()
    Variable,           // not an operation
    Primitive,
    Keyword(Keyword), // not an operation
    NoOp,
}

impl Operation {
    pub(crate) fn new(token: Token) -> Option<Operation> {
        match token.category() {
            Category::Plus
            | Category::Star
            | Category::Slash
            | Category::Minus
            | Category::Percent
            | Category::LessLess
            | Category::GreaterGreater
            | Category::GreaterGreaterGreater
            | Category::Tilde
            | Category::Ampersand
            | Category::Pipe
            | Category::Caret
            | Category::StarStar => Some(Operation::Operator(token.category())),
            Category::Equal
            | Category::MinusEqual
            | Category::PlusEqual
            | Category::SlashEqual
            | Category::StarEqual
            | Category::GreaterGreaterEqual
            | Category::LessLessEqual
            | Category::GreaterGreaterGreaterEqual
            | Category::PlusPlus
            | Category::MinusMinus => Some(Operation::Assign(token.category())),
            Category::String(_) | Category::Number(_) => Some(Operation::Primitive),
            Category::LeftParen | Category::LeftCurlyBracket | Category::Comma => {
                Some(Operation::Grouping(token.category()))
            }
            Category::Identifier(None) => Some(Operation::Variable),
            Category::Identifier(Some(keyword)) => Some(Operation::Keyword(keyword)),
            Category::Comment => Some(Operation::NoOp),
            _ => None,
        }
    }
}
