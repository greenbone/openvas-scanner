use syn::{Ident, ItemFn, Type};

pub struct Attr {
    pub kind: AttrKind,
    pub idents: Vec<Ident>,
}

pub enum AttrKind {
    Named,
    MaybeNamed,
}

pub struct Attrs {
    pub attrs: Vec<Attr>,
}

pub struct ArgsStruct<'a> {
    pub function: &'a ItemFn,
    pub args: Vec<Arg<'a>>,
    pub receiver_type: ReceiverType,
}

pub enum ReceiverType {
    None,
    RefSelf,
    RefMutSelf,
}

pub struct Arg<'a> {
    pub ident: &'a Ident,
    pub ty: &'a Type,
    pub inner_ty: &'a Type,
    pub optional: bool,
    pub kind: ArgKind,
    pub mutable: bool,
}

pub struct NaslSocketsArg {
    pub mutable: bool,
}

pub enum ArgKind {
    Positional(PositionalArg),
    Named(NamedArg),
    MaybeNamed(PositionalArg, NamedArg),
    Context,
    Register,
    NaslSockets(NaslSocketsArg),
    PositionalIterator(PositionalsArg),
    CheckedPositionalIterator(PositionalsArg),
}

impl ArgKind {
    pub fn get_named_arg_name(&self) -> Option<&str> {
        if let Self::Named(name) = self {
            Some(&name.name)
        } else {
            None
        }
    }

    pub fn get_maybe_named_arg_name(&self) -> Option<&str> {
        if let Self::MaybeNamed(_, name) = self {
            Some(&name.name)
        } else {
            None
        }
    }

    pub fn order(&self) -> usize {
        match self {
            ArgKind::Context => 0,
            ArgKind::Register => 0,
            ArgKind::NaslSockets(_) => 1,
            ArgKind::Positional(_) => 2,
            ArgKind::MaybeNamed(_, _) => 3,
            ArgKind::Named(_) => 4,
            ArgKind::PositionalIterator(_) => 5,
            ArgKind::CheckedPositionalIterator(_) => 5,
        }
    }

    pub fn requires_async(&self) -> bool {
        // Keep this intentionally verbose by matching
        // exhaustively, so we remember to check this
        // function again if we introduce a new type.
        match self {
            ArgKind::Positional(_) => false,
            ArgKind::Named(_) => false,
            ArgKind::MaybeNamed(_, _) => false,
            ArgKind::Context => false,
            ArgKind::Register => false,
            ArgKind::PositionalIterator(_) => false,
            ArgKind::CheckedPositionalIterator(_) => false,
            ArgKind::NaslSockets(_) => true,
        }
    }
}

pub struct NamedArg {
    pub name: String,
}

pub struct PositionalArg {
    pub position: usize,
}

pub struct PositionalsArg {
    /// The position of the first argument in the iterator
    pub position: usize,
}
