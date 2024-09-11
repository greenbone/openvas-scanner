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

pub enum ArgKind {
    Positional(PositionalArg),
    Named(NamedArg),
    MaybeNamed(PositionalArg, NamedArg),
    Context,
    Register,
    PositionalIterator,
    CheckedPositionalIterator,
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
}

pub struct NamedArg {
    pub name: String,
}

pub struct PositionalArg {
    pub position: usize,
}
