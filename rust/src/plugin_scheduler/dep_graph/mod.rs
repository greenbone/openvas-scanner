// SPDX-FileCopyrightText: 2023 Greenbone AG
// SPDX-FileCopyrightText: 2018 Nicolas Moutschen
//
// SPDX-License-Identifier: (GPL-2.0-or-later WITH x11vnc-openssl-exception) AND MIT

//! # Library to perform operations over dependency graphs.
//!
//! This library allow running iterative operations over a dependency graph in
//! the correct evaluation order, or will fail if there are a circular
//! dependencies.
//!
//! To use this library, you create a list of [Nodes](trait.Node.html)
//! containing dependency information (which node depends on which). You then
//! create a [DepGraph](struct.DepGraph.html) which will allow you to traverse
//! the graph so that you will always get an item for which all dependencies
//! have been processed.
//!
//! ## Processing order
//!
//! DepGraphs have two methods: one for sequential operations and one for
//! parallel (multi-threaded) operations. In the first case, it's easy to know
//! in which order nodes can be processed, as only one node will be processed
//! at a time. However, in parallel operations, we need to know if a given node
//! is done processing.
//!
//! This leads to a situation where a given worker thread might not be able to
//! pull a node temporarily, as it needs to wait for another worker to finish
//! processing another node.
//!
//! Let's look at the following case:
//!
//! ```text,no_run
//! (A) <-|
//!       |-- [E] <-|-- [G]
//! (B) <-|         |
//!       |-- [F] <-|-- [H]
//! [C] <-|
//! ```
//!
//! In this case, the nodes __E__ and __F__ are dependent on __A__, __B__ and
//! __C__ and __G__ and __H__ are dependent on both __E__ and __F__. If we
//! process the nodes with two workers, they might pick up nodes A and B first.
//! Since these nodes don't have any dependencies, there is no problem right
//! now.
//!
//! ```text,no_run
//! [ ] <-|
//!       |-- [E] <-|-- [G]
//! [ ] <-|         |
//!       |-- [F] <-|-- [H]
//! (C) <-|
//! ```
//!
//! When one of the worker is done, it can immediately start working on node
//! __C__, as it does not have any dependencies. However, when the second
//! worker is done, there are no available nodes for processing: we need to
//! wait until __C__ is processed before we can start working on __E__ or
//! __F__. One of the worker will then stay idle until the other one is done.
//!
//! ```text,no_run
//! [ ] <-|
//!       |-- (E) <-|-- [G]
//! [ ] <-|         |
//!       |-- (F) <-|-- [H]
//! [ ] <-|
//! ```
//!
//! Once that is done, both workers can work on __E__ and __F__. However, if
//! __E__ takes only a fraction of the time compared to __F__, we will end up
//! in the same situation, as there are no nodes without un-processed
//! dependencies.

pub mod error;
mod graph;
#[cfg(feature = "dep-graph-parallel")]
mod graph_par;
mod node;

pub use graph::DepGraph;
#[cfg(feature = "dep-graph-parallel")]
pub use graph_par::Wrapper;
pub use node::Node;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "dep-graph-parallel")]
    use rayon::prelude::*;
    #[cfg(feature = "dep-graph-parallel")]
    use std::time::Duration;

    /// Run against a diamond graph
    ///
    /// ```no_run
    ///   1
    ///  / \
    /// 2   3
    ///  \ /
    ///   4
    /// ```
    #[cfg(feature = "dep-graph-parallel")]
    #[test]
    fn par_diamond_graph() {
        let mut n1 = Node::new("1");
        let mut n2 = Node::new("2");
        let mut n3 = Node::new("3");
        let n4 = Node::new("4");

        n1.add_dep(n2.id());
        n1.add_dep(n3.id());
        n2.add_dep(n4.id());
        n3.add_dep(n4.id());

        let deps = vec![n1, n2, n3, n4];

        let r = DepGraph::new(&deps);
        let result = r.into_par_iter().map(|_| true).collect::<Vec<bool>>();

        assert_eq!(result.len(), deps.len());
    }

    #[cfg(feature = "dep-graph-parallel")]
    #[test]
    fn par_diamond_graph_steps() {
        let mut n1 = Node::new("1");
        let mut n2 = Node::new("2");
        let mut n3 = Node::new("3");
        let n4 = Node::new("4");

        n1.add_dep(n2.id());
        n1.add_dep(n3.id());
        n2.add_dep(n4.id());
        n3.add_dep(n4.id());

        let deps = vec![n1, n2, n3, n4];

        let r = DepGraph::new(&deps);
        let result = r
            .into_par_iter()
            .map(|node_id| (*node_id).parse::<u64>().unwrap())
            .reduce(|| 0, |acc, x| acc + x);

        assert_eq!(result, 10);
    }

    #[cfg(feature = "dep-graph-parallel")]
    #[test]
    fn par_diamond_graph_with_timeout() {
        let mut n1 = Node::new("1");
        let mut n2 = Node::new("2");
        let mut n3 = Node::new("3");
        let n4 = Node::new("4");

        n1.add_dep(n2.id());
        n1.add_dep(n3.id());
        n2.add_dep(n4.id());
        n3.add_dep(n4.id());

        let deps = vec![n1, n2, n3, n4];

        let r = DepGraph::new(&deps);
        let result = r
            .into_par_iter()
            .with_timeout(Duration::from_secs(2))
            .map(|_| true)
            .collect::<Vec<bool>>();

        assert_eq!(result.len(), deps.len());
    }

    #[test]
    fn iter_diamond_graph() {
        let mut n1 = Node::new("1");
        let mut n2 = Node::new("2");
        let mut n3 = Node::new("3");
        let n4 = Node::new("4");

        n1.add_dep(n2.id());
        n1.add_dep(n3.id());
        n2.add_dep(n4.id());
        n3.add_dep(n4.id());

        let deps = vec![n1, n2, n3, n4];

        let r = DepGraph::new(&deps);
        let result = r.into_iter().map(|_| true).collect::<Vec<bool>>();

        assert_eq!(result.len(), deps.len());
    }

    /// 1 000 nodes with 999 depending on one
    #[cfg(feature = "dep-graph-parallel")]
    #[test]
    fn par_thousand_graph() {
        let mut nodes: Vec<Node<_>> = (0..1000).map(|i| Node::new(format!("{}", i))).collect();
        nodes
            .iter_mut()
            .skip(1)
            .for_each(|n| n.add_dep("0".to_string()));

        let r = DepGraph::new(&nodes);
        let result = r.into_par_iter().map(|_| true).collect::<Vec<bool>>();

        assert_eq!(result.len(), nodes.len());
    }

    #[test]
    fn iter_thousand_graph() {
        let mut nodes: Vec<Node<_>> = (0..1000).map(|i| Node::new(format!("{}", i))).collect();
        for item in nodes.iter_mut().take(1000).skip(1) {
            item.add_dep("0".to_string());
        }

        let r = DepGraph::new(&nodes);
        let result = r.into_iter().map(|_| true).collect::<Vec<bool>>();

        assert_eq!(result.len(), nodes.len());
    }

    // #[test]
    // #[should_panic]
    // fn par_circular_graph() {
    //     let mut n1 = Node::new("1");
    //     let mut n2 = Node::new("2");
    //     let mut n3 = Node::new("3");

    //     n1.add_dep(n2.id());
    //     n2.add_dep(n3.id());
    //     n3.add_dep(n1.id());

    //     let deps = vec![n1, n2, n3];

    //     // This should return an exception
    //     let r = DepGraph::new(&deps);
    //     r.into_par_iter().for_each(|_node_id| {});
    // }
}
