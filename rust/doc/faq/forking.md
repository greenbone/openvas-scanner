# Simulated Forking in NASL

In NASL scripts, functions like get_kb_item() and open_sock_tcp() simulate process forking, meaning they transparently start additional script executions.

For exmaple:
```nasl
set_kb_item(name: "test", value: 1);
set_kb_item(name: "test", value: 2);
set_kb_item(name: "test", value: 3);
set_kb_item(name: "test", value: 4);
set_kb_item(name: "test", value: 5);
display(get_kb_item("test"));
display('hi');
```

With scannerctl, the script runs sequentially, displaying results one by one:
```bash
> scannerctl execute script get_kb_item.nasl
5
1
2
3
4
hi
hi
hi
hi
hi
```

In contrast, openvas-nasl forks the script, executing statements in parallel:

```bash
> openvas-nasl -X get_kb_item.nasl
** WARNING : packet forgery will not work
** as NASL is not running as root
lib  nasl-Message: 13:34:38.456: 5
lib  nasl-Message: 13:34:38.456: hi
lib  nasl-Message: 13:34:38.458: 4
lib  nasl-Message: 13:34:38.458: hi
lib  nasl-Message: 13:34:38.460: 3
lib  nasl-Message: 13:34:38.460: hi
lib  nasl-Message: 13:34:38.461: 2
lib  nasl-Message: 13:34:38.461: hi
lib  nasl-Message: 13:34:38.463: 1
lib  nasl-Message: 13:34:38.463: hi
lib  nasl-Message: 13:34:38.464:
lib  nasl-Message: 13:34:38.464: hi
```

The `scannerctl` approach is memory-efficient, storing only active registry results, while `openvas-nasl` allows parallel execution by duplicating execution paths.

## Developing Builtin Functions with Forking 

To simulate forking in a NASL builtin function, developers should return `NaslValue::Fork`, which holds a `Vec` of `NaslValues` for separate execution paths. For example:

```rust
/// NASL function to get a knowledge base
#[nasl_function]
fn get_kb_item(c: &Context, key: &str) -> Result<NaslValue, FunctionErrorKind> {
    c.retriever()
        .retrieve(c.key(), Retrieve::KB(key.to_string()))
        .map(|r| {
            r.into_iter()
                .filter_map(|x| match x {
                    Field::NVT(_) | Field::NotusAdvisory(_) | Field::Result(_) => None,
                    Field::KB(kb) => Some(kb.value.into()),
                })
                .collect::<Vec<_>>()
        })
        .map(NaslValue::Fork)
        .map_err(|e| e.into())
}
```

## Internal Handling of Forking
The interpreter checks if a function is called from the main script (index 0). If so, it creates new execution blocks for each NaslValue::Fork entry, cloning the registry and tracking the position to avoid re-running statements.


```rust
let result = match self.ctxconfigs.nasl_fn_execute(name, self.register()).await {
    Some(r) => {
        if let Ok(NaslValue::Fork(mut x)) = r {
            Ok(if let Some(r) = x.pop() {
                // this is a proposal for the case that the caller is immediately executing
                // if not the position needs to be reset
                if self.index == 0 {
                    let position = self.position().current_init_statement();
                    for i in x {
                        tracing::trace!(return_value=?i, return_position=?self.position(), interpreter_position=?position, "creating interpreter instance" );
                        self.run_specific.push(RunSpecific {
                            register: self.register().clone(),
                            position: position.clone(),
                            skip_until_return: Some((self.position().clone(), i)),
                        });
                    }
                } else {
                    tracing::trace!(
                        index = self.index,
                        "we only allow expanding of executions (fork) on root instance"
                    );
                }
                tracing::trace!(return_value=?r, "returning interpreter instance" );
                r
            } else {
                NaslValue::Null
            })
        } else {
            r.map_err(|x| FunctionError::new(name, x).into())
        }
    }
  ...
}
```

Each interpreter instance retrieves the stored NaslValue from skip_until_return before proceeding with the script:

```rust
/// Evaluates the next statement
pub async fn next_statement(&mut self) -> Option<InterpretResult> {
    self.statement = None;
    match self.lexer.next() {
        Some(Ok(nstmt)) => {
            let results = Some(self.interpreter.retry_resolve_next(&nstmt, 5).await);
            self.statement = Some(nstmt);
            results
        }
        Some(Err(err)) => Some(Err(err.into())),
        None => None,
    }
}

async fn ne<LeftMouse>t_(&mut self) -> Option<InterpretResult> {
    if let Some(stmt) = self.statement.as_ref() {
        match self.interpreter.next_interpreter() {
            Some(inter) => Some(inter.retry_resolve(stmt, 5).await),
            None => self.next_statement().await,
        }
    } else {
        self.next_statement().await
    }
}

/// Creates a stream over the results of the statements
pub fn stream(self) -> impl Stream<Item = InterpretResult> + 'b
where
    'a: 'b,
{
    Box::pin(stream::unfold(self, |mut s| async move {
        s.next_().await.map(|x| (x, s))
    }))
}

```

