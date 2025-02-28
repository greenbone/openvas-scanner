# Forking behavior.

A peculiar property of the NASL programming language is the forking.
From a user point of view, forking happens whenever certain builtin 
functions are called. An example of such a function is `get_kb_item`.
This seemingly innocent function retrieves an item from the knowledge base, given a key. 
As an example, consider the following NASL code:
```nasl
set_kb_item(name: "foo", value: "bar1");
set_kb_item(name: "foo", value: "bar2");
display(get_kb_item("foo"));
```

Since the key `"foo"` has more than a single entry in the knowledge base, the call to
`get_kb_item` will implicitly perform forking. Effectively, after the call to `get_kb_item`, the interpreter will behave as if we had run two
identical scripts that only differ in the value that was returned by `get_kb_item("foo")`. From that point on, every statement will be executed
twice twice.
The above script would therefore print:
```
bar1
bar2
```

Multiple forks can take place at the same time. For example, this code
```nasl
set_kb_item(name: "port", value: 1);
set_kb_item(name: "port", value: 2);
set_kb_item(name: "host", value: "a");
set_kb_item(name: "host", value: "b");
display(get_kb_item("host") + get_kb_item("port"));
```

will result in

```
a:1
a:2
b:1
b:2
```

being displayed.

## Guarantees
Due to its implicit nature, forking leaves quite a few decisions open to the concrete implementation. In the following we will briefly discuss some of these decisions along with the way that they are currently implemented in the openvasd implementation of NASL. However, none of these should be relied upon:

### Statement execution
When the interpreter forks into multiple sub-interpreters, the execution order is `(statement1, interpreter1), (statement1, interpreter2), (statement1, interpreter3), ... (statement2, interpreter1), (statement2, interpreter2), (statement2, interpreter3), ...`. 

### Order of multiple forks.
If multiple forks are created:
```nasl
get_kb_item("a");
get_kb_item("b");
```
the order in which they are created will be `(a1, b1), (a1, b2), (a1, b3), ... (a2, b1), (a2, b2), (a2, b3), ...`.

### Different branches
If different forks run into different branches within the statement in which they were created, the interpreter will return an error, resulting in stopped execution of the script. For example the script
```nasl
set_kb_item(name: "test1", value: 1);
set_kb_item(name: "test1", value: 2);
set_kb_item(name: "test2", value: 3);
set_kb_item(name: "test2", value: 4);
set_kb_item(name: "test3", value: 5);
set_kb_item(name: "test3", value: 6);
if (get_kb_item("test1") == 1) {
    get_kb_item("test2");
}
else {
    get_kb_item("test3");
}
```
will result in an interpreter error. This is done in order to prevent ambiguous code that could result in very unexpected behavior from working.
In order to avoid situations like this, avoid relying on such conditional structures.

### Forks never die
Forks always remain alive until the end of a script. Once a script forks, each fork will run until it exits. There is no concept to fork only for a specified subsection of the code. Such behavior can be achieved by a futuristic language feature called "loops".


### Builtin functions that fork
As of writing, the only builtin functions that cause forks to happen are:
1. `get_host_name`
2. `get_kb_item`
3. `open_sock_tcp`


### Context, storage and memory in forks
In the current implementation, forks all share the same context. There is no concept to have separate contexts or storages for different forks.
