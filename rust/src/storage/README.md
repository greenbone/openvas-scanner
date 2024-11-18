# storage

```

```


Is a specialized library to handle data from the nasl-interpreter to the storage / distribution implementation.

To be able to introduce new distribution implementations the `Dispatcher` must be implement.

The `Field` enum required by `dispatch` method describes fields to be distributed.

The reason that it uses field descriptions rather than structs are two fold:
1. it allows the usage of streaming distribution
2. it makes it easier to store information immediately on execution

Since we sometimes have the requirement to just store when all information is available the `on_exit` must be called when the interpreter finishes.

A simplified example on how to write a storage implementation can be found in `DefaultDispatcher`

## Build

Run `cargo test` to test and `cargo build --release` to build it.
