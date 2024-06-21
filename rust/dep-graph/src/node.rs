// SPDX-FileCopyrightText: 2023 Greenbone AG
// SPDX-FileCopyrightText: 2018 Nicolas Moutschen
//
// SPDX-License-Identifier: (GPL-2.0-or-later WITH x11vnc-openssl-exception) AND MIT

use std::cmp::PartialEq;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;

/// Single node in a dependency graph, which might have dependencies or be
/// be used as a dependency by other nodes.
///
/// A node is represented by a unique identifier and may contain a list of
/// dependencies.
#[derive(Clone, Debug)]
pub struct Node<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync,
{
    id: I,
    deps: HashSet<I>,
}

impl<I> Node<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync,
{
    pub fn new(id: I) -> Node<I> {
        Node {
            id,
            deps: HashSet::default(),
        }
    }

    pub fn id(&self) -> &I {
        &self.id
    }
    pub fn deps(&self) -> &HashSet<I> {
        &self.deps
    }
    pub fn add_dep(&mut self, dep: I) {
        self.deps.insert(dep);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_node() {
        let node = Node::new("node");

        assert_eq!(*node.id(), "node");
        assert_eq!(node.deps().len(), 0);
    }

    #[test]
    fn empty_usize_node() {
        let node: Node<usize> = Node::new(42);

        assert_eq!(*node.id(), 42);
        assert_eq!(node.deps.len(), 0);
    }

    #[test]
    fn one_dep() {
        let mut root = Node::new("root");
        let dep1 = Node::new("dep1");

        root.add_dep(dep1.id());

        assert_eq!(root.deps().len(), 1);
    }

    #[test]
    fn two_deps() {
        let mut root = Node::new("root");
        let dep1 = Node::new("dep1");
        let dep2 = Node::new("dep2");

        root.add_dep(dep1.id());
        root.add_dep(dep2.id());

        assert_eq!(root.deps().len(), 2);
        assert_eq!(dep1.deps().len(), 0);
        assert_eq!(dep2.deps().len(), 0);
    }

    #[test]
    fn diamonds() {
        let mut root = Node::new("root");
        let mut dep1 = Node::new("dep1");
        let mut dep2 = Node::new("dep2");
        let leaf = Node::new("leaf");

        root.add_dep(dep1.id());
        root.add_dep(dep2.id());
        dep1.add_dep(leaf.id());
        dep2.add_dep(leaf.id());

        assert_eq!(root.deps().len(), 2);
        assert_eq!(dep1.deps().len(), 1);
        assert_eq!(dep2.deps().len(), 1);
        assert_eq!(leaf.deps().len(), 0);
    }
}
