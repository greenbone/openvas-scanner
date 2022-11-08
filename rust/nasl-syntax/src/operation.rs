use crate::token::{Category, Keyword, Token};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Operation {
    Operator(Category),
    AssignOperator(Category, Category, u8),
    Assign(Category),
    Grouping(Category), // grouping operator ()
    Variable(Token),    // not an operation
    Primitive(Token),
    Keyword(Keyword), // not an operation
    NoOp(Token),
}

impl Operation {
    pub(crate) fn new(token: Token) -> Option<Operation> {
        match token.category() {
            Category::Plus
            | Category::Star
            | Category::Slash
            | Category::Minus
            | Category::Percent
            | Category::StarStar => Some(Operation::Operator(token.category())),
            Category::PlusPlus => Some(Operation::AssignOperator(
                Category::PlusPlus,
                Category::Plus,
                1,
            )),
            Category::MinusMinus => Some(Operation::AssignOperator(
                Category::MinusMinus,
                Category::Minus,
                1,
            )),
            Category::Equal => Some(Operation::Assign(Category::Equal)),
            Category::String(_) | Category::Number(_) => Some(Operation::Primitive(token)),
            Category::LeftParen | Category::LeftCurlyBracket | Category::Comma => {
                Some(Operation::Grouping(token.category()))
            }
            Category::Identifier(None) => Some(Operation::Variable(token)),
            Category::Identifier(Some(keyword)) => Some(Operation::Keyword(keyword)),
            Category::Comment => Some(Operation::NoOp(token)),
            _ => None,
        }
    }
}
