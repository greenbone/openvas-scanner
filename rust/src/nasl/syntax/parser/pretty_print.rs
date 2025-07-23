use crate::nasl::{
    syntax::{Ident, LiteralKind, token::Literal},
    utils::function::bytes_to_str,
};

use super::super::grammar::{
    AnonymousFnArg, Array, ArrayAccess, Assignment, Atom, Binary, Block, Exit, Expr, FnArg, FnCall,
    FnDecl, For, ForEach, If, Include, Increment, IncrementKind, NamedFnArg, PlaceExpr, Repeat,
    Return, Statement, Unary, VarScope, VarScopeDecl, While,
};

use std::fmt::{Display, Formatter, Result};

impl Display for Statement {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Statement::VarScopeDecl(x) => write!(f, "{x}"),
            Statement::FnDecl(x) => write!(f, "{x}"),
            Statement::ExprStmt(x) => write!(f, "{x}"),
            Statement::Block(x) => write!(f, "{x}"),
            Statement::While(x) => write!(f, "{x}"),
            Statement::Repeat(x) => write!(f, "{x}"),
            Statement::ForEach(x) => write!(f, "{x}"),
            Statement::For(x) => write!(f, "{x}"),
            Statement::If(x) => write!(f, "{x}"),
            Statement::Include(x) => write!(f, "{x}"),
            Statement::Exit(x) => write!(f, "{x}"),
            Statement::Return(x) => write!(f, "{x}"),
            Statement::Break => write!(f, "break"),
            Statement::Continue => write!(f, "continue"),
            Statement::NoOp => write!(f, ""),
        }?;
        match self {
            Statement::VarScopeDecl(_)
            | Statement::ExprStmt(_)
            | Statement::Repeat(_)
            | Statement::Include(_)
            | Statement::Exit(_)
            | Statement::Return(_)
            | Statement::Break
            | Statement::Continue
            | Statement::NoOp => write!(f, ";"),
            Statement::FnDecl(_)
            | Statement::Block(_)
            | Statement::While(_)
            | Statement::ForEach(_)
            | Statement::For(_)
            | Statement::If(_) => Ok(()),
        }
    }
}

impl Display for VarScopeDecl {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self.scope {
            VarScope::Local => write!(f, "local_var ")?,
            VarScope::Global => write!(f, "global_var ")?,
        };
        for (i, ident) in self.idents.iter().enumerate() {
            write!(f, "{ident}")?;
            if i + 1 != self.idents.len() {
                write!(f, ", ")?;
            }
        }
        Ok(())
    }
}

impl Display for Expr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Expr::Atom(atom) => write!(f, "{atom}"),
            Expr::Binary(binary) => write!(f, "{binary}"),
            Expr::Unary(unary) => write!(f, "{unary}"),
            Expr::Assignment(assign) => write!(f, "{} {} {}", assign.lhs, assign.op, assign.rhs),
        }
    }
}

impl Display for Assignment {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{} {} {}", self.lhs, self.op, self.rhs)
    }
}

impl Display for PlaceExpr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let negation = if self.negate { "!" } else { "" };
        if self.array_accesses.is_empty() {
            write!(f, "{}{}", negation, self.ident)
        } else {
            write!(
                f,
                "{}{}{}",
                negation,
                self.ident,
                self.array_accesses
                    .iter()
                    .map(|e| format!("[{e}]"))
                    .collect::<String>()
            )
        }
    }
}

impl Display for Binary {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "({} {} {})", self.lhs, self.op, self.rhs)
    }
}

impl Display for Unary {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "({}{})", self.op, self.rhs)
    }
}

impl Display for Atom {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Atom::Literal(lit) => write!(f, "{lit}"),
            Atom::Ident(ident) => write!(f, "{ident}"),
            Atom::Array(arr) => write!(f, "{arr}"),
            Atom::ArrayAccess(access) => write!(f, "{}[{}]", access.lhs_expr, access.index_expr),
            Atom::FnCall(call) => write!(f, "{call}"),
            Atom::Increment(inc) => write!(f, "{inc}"),
        }
    }
}

impl Display for Increment {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self.kind {
            IncrementKind::Prefix => write!(f, "{}{}", self.op, self.expr),
            IncrementKind::Postfix => write!(f, "{}{}", self.expr, self.op),
        }
    }
}

impl Display for Array {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let items = self
            .items
            .items
            .iter()
            .map(|e| format!("{e}"))
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "[{items}]")
    }
}

impl Display for ArrayAccess {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}[{}]", self.lhs_expr, self.index_expr)
    }
}

impl Display for FnCall {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let args = self
            .args
            .items
            .iter()
            .map(|arg| format!("{arg}"))
            .collect::<Vec<_>>()
            .join(", ");
        if let Some(repeats) = &self.num_repeats {
            write!(f, "{}({}) x {}", self.fn_name, args, repeats)
        } else {
            write!(f, "{}({})", self.fn_name, args)
        }
    }
}

impl Display for FnArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            FnArg::Anonymous(arg) => write!(f, "{arg}"),
            FnArg::Named(arg) => write!(f, "{arg}"),
        }
    }
}

impl Display for AnonymousFnArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.expr)
    }
}

impl Display for NamedFnArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}: {}", self.ident, self.expr)
    }
}

impl<T: Display> Display for Block<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        writeln!(f, "{{")?;
        // A little ugly and slow but this takes care of
        // recursive indentation
        let mut s = String::new();
        for item in &self.items {
            s.push_str(&format!("{item}\n"));
        }
        if s.lines().count() > 0 {
            writeln!(
                f,
                "{}",
                s.lines()
                    .map(|line| format!("  {line}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            )?;
        }
        write!(f, "}}")
    }
}

impl Display for While {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "while ({}) {}", self.condition, self.block)
    }
}

impl Display for Repeat {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "repeat {} until ({})", self.block, self.condition)
    }
}

impl Display for ForEach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "foreach {} ({}) {}", self.var, self.array, self.block)
    }
}

impl Display for For {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let initializer = match self.initializer {
            Some(ref initializer) => format!("{initializer}"),
            None => ";".to_string(),
        };
        let increment = match self.increment {
            Some(ref increment) => format!("{increment}"),
            None => "".to_string(),
        };
        write!(
            f,
            "for ({initializer} {}; {increment}) {}",
            self.condition, self.block
        )
    }
}

impl Display for If {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (i, (cond, block)) in self.if_branches.iter().enumerate() {
            if i == 0 {
                write!(f, "if ({cond}) {block}")?;
            } else {
                write!(f, " else if ({cond}) {block}")?;
            }
        }
        if let Some(else_block) = &self.else_branch {
            write!(f, " else {else_block}")?;
        }
        Ok(())
    }
}

impl Display for FnDecl {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let args = self
            .args
            .items
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "function {} ({}) {}", self.fn_name, args, self.block)
    }
}

impl Display for Include {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "include(\'{}\')", self.path)
    }
}

impl Display for Exit {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "exit({})", self.expr)
    }
}

impl Display for Return {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        if let Some(ref expr) = self.expr {
            write!(f, "return ({expr})")
        } else {
            write!(f, "return")
        }
    }
}

impl Display for Ident {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.to_str())
    }
}

impl Display for Literal {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match &self.kind {
            LiteralKind::String(s) => write!(f, "\"{s}\""),
            LiteralKind::Data(d) => write!(f, "'{}'", bytes_to_str(d)),
            LiteralKind::Number(n) => write!(f, "{n}"),
            LiteralKind::IPv4Address(ip) => write!(f, "{ip}"),
            LiteralKind::Boolean(b) => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            LiteralKind::Null => write!(f, "Null"),
            LiteralKind::AttackCategory(a) => write!(f, "{a}"),
            LiteralKind::FCTAnonArgs => write!(f, "_FCT_ANON_ARGS"),
        }
    }
}
