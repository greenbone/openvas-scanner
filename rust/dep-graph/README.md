# Dependency Graph

Author: Nicolas Moutschen <nicolas.moutschen@gmail.com>

Origin: https://github.com/nmoutschen/dep-graph

This is a rust library to perform iterative operations over dependency graphs.

## Usage

This library supports both sequential and parallel (multi-threaded) operations out of the box. By default, multi-threaded operations will run a number of threads equal to the number of cores.

### Parallel operations

Here is a simple example on how to use this library:

```rust
use dep_graph::{Node, DepGraph};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

// Create a list of nodes
let mut root = Node::new("root");
let mut dep1 = Node::new("dep1");
let mut dep2 = Node::new("dep2");
let leaf = Node::new("leaf");

// Map their connections
root.add_dep(dep1.id());
root.add_dep(dep2.id());
dep1.add_dep(leaf.id());
dep2.add_dep(leaf.id());

// Create a graph
let nodes = vec![root, dep1, dep2, leaf];

// Print the name of all nodes in the dependency graph.
// This will parse the dependency graph sequentially
{
    let graph = DepGraph::new(&nodes);
    graph
        .into_iter()
        .for_each(|node| {
            println!("{:?}", node)
        });
}

// This is the same as the previous command, excepts it leverages rayon
// to process them in parallel as much as possible.
#[cfg(feature = "parallel")]
{
    let graph = DepGraph::new(&nodes);
    graph
        .into_par_iter()
        .for_each(|node| {
            // The node is a dep_graph::Wrapper object, not a String.
            // We need to use `*node` to get its value.
            println!("{:?}", *node)
        });
}
```
