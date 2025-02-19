use crate::nasl::{
    interpreter::InterpretError,
    prelude::NaslValue,
    syntax::{Lexer, Statement},
    Register,
};

pub struct Interpreter<'code> {
    _register: Register,
    lexer: Lexer<'code>,
}

pub type InterpretResult = Result<NaslValue, InterpretError>;

impl<'code> Interpreter<'code> {
    /// Creates a new Interpreter
    pub fn new(_register: Register, lexer: Lexer<'code>) -> Self {
        Interpreter { _register, lexer }
    }

    pub fn make_fork(&self, val: NaslValue) -> Interpreter<'code> {
        Interpreter {
            _register: self._register.clone(),
            lexer: self.lexer.clone(),
        };
        todo!("{}", val);
    }

    pub fn execute_next_statement(&mut self) -> Option<InterpretResult> {
        match self.lexer.next() {
            Some(Ok(stmt)) => self.execute_statement(&stmt),
            Some(Err(err)) => Some(Err(err.into())),
            None => None,
        }
    }

    fn execute_statement(&self, statement: &Statement) -> Option<InterpretResult> {
        todo!()
        // match statement.kind() {
        //     Include(inc) => Box::pin(self.include(inc)).await,
        //     Array(position) => self.resolve_array(statement, position.clone()).await,
        //     Exit(stmt) => self.resolve_exit(stmt).await,
        //     Return(stmt) => self.resolve_return(stmt).await,
        //     NamedParameter(..) => {
        //         unreachable!("named parameter should not be an executable statement.")
        //     }
        //     For(assignment, condition, update, body) => {
        //         Box::pin(self.for_loop(assignment, condition, update, body)).await
        //     }
        //     While(condition, body) => Box::pin(self.while_loop(condition, body)).await,
        //     Repeat(body, condition) => Box::pin(self.repeat_loop(body, condition)).await,
        //     ForEach(variable, iterable, body) => {
        //         Box::pin(self.for_each_loop(variable, iterable, body)).await
        //     }
        //     FunctionDeclaration(name, args, exec) => {
        //         self.declare_function(name, args.children(), exec)
        //     }
        //     Primitive => self.resolve_primitive(statement),
        //     Variable => self.resolve_variable(statement),
        //     Call(arguments) => Box::pin(self.call(statement, arguments.children())).await,
        //     Declare(stmts) => self.declare_variable(statement.as_token(), stmts),
        //     Parameter(x) => self.resolve_parameter(x).await,
        //     Assign(cat, order, left, right) => Box::pin(self.assign(cat, order, left, right)).await,
        //     Operator(sign, stmts) => Box::pin(self.operator(sign, stmts)).await,
        //     If(condition, if_block, _, else_block) => {
        //         self.resolve_if(condition, if_block, else_block.clone())
        //             .await
        //     }
        //     Block(blocks) => self.resolve_block(blocks).await,
        //     NoOp => Ok(NaslValue::Null),
        //     EoF => Ok(NaslValue::Null),
        //     AttackCategory => self.resolve_attack_category(statement),
        //     Continue => Ok(NaslValue::Continue),
        //     Break => Ok(NaslValue::Break),
        // }
        // .map_err(|e| {
        //     if e.origin.is_none() {
        //         InterpretError::from_statement(statement, e.kind)
        //     } else {
        //         e
        //     }
        // })
    }
}
