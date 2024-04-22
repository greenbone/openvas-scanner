// SPDX-FileCopyrightText: 2023 Greenbone AG
// SPDX-FileCopyrightText: 2018 Nicolas Moutschen
//
// SPDX-License-Identifier: (GPL-2.0-or-later WITH x11vnc-openssl-exception) AND MIT

use crate::{error::Error, Node};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::Hash;
use std::sync::{Arc, RwLock};

pub type InnerDependencyMap<I> = HashMap<I, HashSet<I>>;
pub type DependencyMap<I> = Arc<RwLock<InnerDependencyMap<I>>>;

/// Dependency graph
#[derive(Debug, Default)]
pub struct DepGraph<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    pub ready_nodes: Vec<I>,
    pub deps: DependencyMap<I>,
    pub rdeps: DependencyMap<I>,
}

impl<I> DepGraph<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    /// Create a new DepGraph based on a vector of edges.
    pub fn new(nodes: &[Node<I>]) -> Self {
        let (deps, rdeps, ready_nodes) = DepGraph::parse_nodes(nodes);

        DepGraph {
            ready_nodes,
            deps,
            rdeps,
        }
    }

    fn parse_nodes(nodes: &[Node<I>]) -> (DependencyMap<I>, DependencyMap<I>, Vec<I>) {
        let mut deps = InnerDependencyMap::<I>::default();
        let mut rdeps = InnerDependencyMap::<I>::default();
        let mut ready_nodes = Vec::<I>::default();

        for node in nodes {
            deps.insert(node.id().clone(), node.deps().clone());

            if node.deps().is_empty() {
                ready_nodes.push(node.id().clone());
            } else {
                for node_dep in node.deps() {
                    rdeps
                        .entry(node_dep.clone())
                        .or_default()
                        .insert(node.id().clone());
                }
            }
        }

        (
            Arc::new(RwLock::new(deps)),
            Arc::new(RwLock::new(rdeps)),
            ready_nodes,
        )
    }
}

impl<I: Clone> Clone for DepGraph<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            ready_nodes: self.ready_nodes.clone(),
            // clone the inner HashMap so that a new iteration can be started
            deps: Arc::new(RwLock::new(self.deps.read().unwrap().clone())),
            rdeps: Arc::new(RwLock::new(self.rdeps.read().unwrap().clone())),
        }
    }
}

impl<I> IntoIterator for DepGraph<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    type Item = I;
    type IntoIter = DepGraphIter<I>;

    fn into_iter(self) -> Self::IntoIter {
        DepGraphIter::<I>::new(self.ready_nodes, self.deps, self.rdeps)
    }
}

#[derive(Clone)]
pub struct DepGraphIter<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    ready_nodes: Vec<I>,
    deps: DependencyMap<I>,
    rdeps: DependencyMap<I>,
}

impl<I> DepGraphIter<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    pub fn new(ready_nodes: Vec<I>, deps: DependencyMap<I>, rdeps: DependencyMap<I>) -> Self {
        Self {
            ready_nodes,
            deps,
            rdeps,
        }
    }
}

impl<I> Iterator for DepGraphIter<I>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    type Item = I;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(id) = self.ready_nodes.pop() {
            // Remove dependencies and retrieve next available nodes, if any.
            let next_nodes = remove_node_id::<I>(id.clone(), &self.deps, &self.rdeps).unwrap();

            // Push ready nodes
            self.ready_nodes.extend_from_slice(&next_nodes);

            // Return the node ID
            Some(id)
        } else {
            // No available node
            None
        }
    }
}

/// Remove all references to the node ID in the dependencies.
///
pub fn remove_node_id<I>(
    id: I,
    deps: &DependencyMap<I>,
    rdeps: &DependencyMap<I>,
) -> Result<Vec<I>, Error>
where
    I: Clone + fmt::Debug + Eq + Hash + PartialEq + Send + Sync + 'static,
{
    let mut deps = deps.write().unwrap();

    let next_nodes = if let Some(rdep_ids) = rdeps.read().unwrap().get(&id) {
        let next_nodes = rdep_ids
            .iter()
            .filter_map(|rdep_id| {
                let rdep = match deps.get_mut(rdep_id) {
                    Some(rdep) => rdep,
                    None => return None,
                };

                rdep.remove(&id);

                if rdep.is_empty() {
                    Some(rdep_id.clone())
                } else {
                    None
                }
            })
            .collect();

        next_nodes
    } else {
        // If no node depends on a node, it will not appear in rdeps.
        vec![]
    };

    // Remove the current node from the list of dependencies.
    deps.remove(&id);

    Ok(next_nodes)
}
