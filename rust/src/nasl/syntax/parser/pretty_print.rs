use crate::nasl::{
    syntax::{Ident, token::Literal},
    utils::function::bytes_to_str,
};

use super::grammar::{
    AnonymousFnArg, Array, ArrayAccess, Assignment, Atom, Binary, Block, Exit, Expr, FnArg, FnCall,
    FnDecl, For, Foreach, If, Include, Increment, IncrementKind, NamedFnArg, PlaceExpr, Repeat,
    Return, Stmt, Unary, VarScope, VarScopeDecl, While,
};

use std::fmt::{Display, Formatter, Result};

impl Display for Stmt {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Stmt::VarScopeDecl(x) => write!(f, "{}", x),
            Stmt::FnDecl(x) => write!(f, "{}", x),
            Stmt::ExprStmt(x) => write!(f, "{}", x),
            Stmt::Block(x) => write!(f, "{}", x),
            Stmt::While(x) => write!(f, "{}", x),
            Stmt::Repeat(x) => write!(f, "{}", x),
            Stmt::Foreach(x) => write!(f, "{}", x),
            Stmt::For(x) => write!(f, "{}", x),
            Stmt::If(x) => write!(f, "{}", x),
            Stmt::Include(x) => write!(f, "{}", x),
            Stmt::Exit(x) => write!(f, "{}", x),
            Stmt::Return(x) => write!(f, "{}", x),
            Stmt::Break => write!(f, "break"),
            Stmt::Continue => write!(f, "continue"),
            Stmt::NoOp => write!(f, ""),
        }?;
        match self {
            Stmt::VarScopeDecl(_)
            | Stmt::ExprStmt(_)
            | Stmt::Repeat(_)
            | Stmt::Include(_)
            | Stmt::Exit(_)
            | Stmt::Return(_)
            | Stmt::Break
            | Stmt::Continue
            | Stmt::NoOp => write!(f, ";"),
            Stmt::FnDecl(_)
            | Stmt::Block(_)
            | Stmt::While(_)
            | Stmt::Foreach(_)
            | Stmt::For(_)
            | Stmt::If(_) => Ok(()),
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
            write!(f, "{}", ident)?;
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
            Expr::Atom(atom) => write!(f, "{}", atom),
            Expr::Binary(binary) => write!(f, "{}", binary),
            Expr::Unary(unary) => write!(f, "{}", unary),
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
        if self.array_accesses.is_empty() {
            write!(f, "{}", self.ident)
        } else {
            write!(
                f,
                "{}{}",
                self.ident,
                self.array_accesses
                    .iter()
                    .map(|e| format!("[{}]", e))
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
            Atom::Literal(lit) => write!(f, "{}", lit),
            Atom::Ident(ident) => write!(f, "{}", ident),
            Atom::Array(arr) => write!(f, "{}", arr),
            Atom::ArrayAccess(access) => write!(f, "{}[{}]", access.lhs_expr, access.index_expr),
            Atom::FnCall(call) => write!(f, "{}", call),
            Atom::Increment(inc) => write!(f, "{}", inc),
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
            .map(|e| format!("{}", e))
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "[{}]", items)
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
            .map(|arg| format!("{}", arg))
            .collect::<Vec<_>>()
            .join(", ");
        if let Some(repeats) = &self.num_repeats {
            write!(f, "{}({}) x {}", self.fn_expr, args, repeats)
        } else {
            write!(f, "{}({})", self.fn_expr, args)
        }
    }
}

impl Display for FnArg {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            FnArg::Anonymous(arg) => write!(f, "{}", arg),
            FnArg::Named(arg) => write!(f, "{}", arg),
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
            s.push_str(&format!("{}\n", item));
        }
        if s.lines().count() > 0 {
            write!(
                f,
                "{}\n",
                s.lines()
                    .map(|line| format!("  {}", line))
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

impl Display for Foreach {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "foreach {} ({}) {}", self.var, self.array, self.block)
    }
}

impl Display for For {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "for ({} {}; {}) {}",
            self.initializer, self.condition, self.increment, self.block
        )
    }
}

impl Display for If {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        for (i, (cond, block)) in self.if_branches.iter().enumerate() {
            if i == 0 {
                write!(f, "if ({}) {}", cond, block)?;
            } else {
                write!(f, " else if ({}) {}", cond, block)?;
            }
        }
        if let Some(else_block) = &self.else_branch {
            write!(f, " else {}", else_block)?;
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
        write!(f, "include({})", self.path)
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
            write!(f, "return ({})", expr)
        } else {
            write!(f, "return")
        }
    }
}

impl Display for Ident {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(f, "{}", self.0)
    }
}

impl Display for Literal {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Literal::String(s) => write!(f, "\"{}\"", s),
            Literal::Data(d) => write!(f, "'{}'", bytes_to_str(d)),
            Literal::Number(n) => write!(f, "{}", n),
            Literal::IPv4Address(ip) => write!(f, "{}", ip),
            Literal::Boolean(b) => write!(f, "{}", if *b { "TRUE" } else { "FALSE" }),
            Literal::Null => write!(f, "Null"),
        }
    }
}
