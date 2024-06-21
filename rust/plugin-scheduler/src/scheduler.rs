// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use std::{collections::HashMap, vec};

use dep_graph::{DepGraph, Node, Wrapper};
use generic_array::{sequence::GenericSequence, GenericArray};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

use crate::{
    error::SchedulerError,
    plugin::{Phase, Plugin, PluginCollection},
};

/// Phase base Plugin Scheduler. A new instance can be created with the [PluginScheduler::create()] Method. Providing
/// a plugin collection and a plugin list, it will automatically create an execution order for
/// each execution phase. Those orders can be processes with the execution methods provided, either
/// sequential with execute or in parallel with execute_parallel.
/// All errors occurring during the creation will be stored internally and can be retrieved with
/// [PluginScheduler::get_errors()]. Based on the error, the caller can decide whether to continue the execution or
/// interrupt further processing.
pub struct PluginScheduler<C>
where
    C: Phase + Clone,
{
    pub dependency_graphs: GenericArray<Option<DepGraph<String>>, C::LEN>,
    pub errors: Vec<(String, SchedulerError<C>)>,
}

impl<C> PluginScheduler<C>
where
    C: Phase + Clone,
{
    /// Recursively collects all dependencies of a Plugin. Also creates a node for the requested Plugin
    /// and returns either a List of all Plugin dependencies (including itself) or an error. An error
    /// means either a cycle within a dependency chain, a dependency was not found in the collection
    /// or an error regarding the execution order of the plugins. See [`crate::error::SchedulerError`]
    /// for more details.
    fn collect_deps<PC, P>(
        plugin_collection: &PC,
        plugin: &P,
        entry_map: &mut HashMap<String, Result<C, SchedulerError<C>>>,
        dependency_chain: &mut Vec<String>,
    ) -> Result<Vec<(C, Node<String>)>, SchedulerError<C>>
    where
        PC: PluginCollection<P, C>,
        P: Plugin<C>,
        C: Phase + PartialEq + Clone,
    {
        let mut node = Node::new(plugin.get_id());

        let mut dep_entries: Vec<(C, Node<String>)> = vec![];

        // Iterate through dependencies
        for dep in plugin.get_dependencies() {
            // Check if dependency is already included
            if entry_map.contains_key(&dep) {
                match &entry_map[&dep] {
                    Err(err) => return Err(err.clone()),
                    Ok(cat) => {
                        if plugin.get_category() == *cat {
                            node.add_dep(dep)
                        }
                        continue;
                    }
                }
            }

            // Get plugin from collection
            let dependency = match plugin_collection.get_plugin(&dep) {
                Some(x) => x,
                None => {
                    let err =
                        SchedulerError::PluginNotFound(dependency_chain.to_owned(), dep.clone());
                    entry_map.insert(dep.clone(), Err(err.clone()));
                    return Err(err);
                }
            };

            // Check for dependency cycle
            if dependency_chain.contains(&dependency.get_id()) {
                dependency_chain.push(dependency.get_id());
                return Err(SchedulerError::DependencyCycle(dependency_chain.to_owned()));
            }

            dependency_chain.push(dependency.get_id());

            // Collect dependencies for plugin
            match Self::collect_deps(plugin_collection, &dependency, entry_map, dependency_chain) {
                // No errors found, add plugin to dependency entries
                Ok(mut entries) => {
                    dep_entries.append(&mut entries);
                }
                // Error found, add error to scheduler errors
                Err(e) => {
                    entry_map.insert(plugin.get_id(), Err(e.clone()));
                    return Err(e);
                }
            }

            dependency_chain.pop();

            if plugin.get_category() == dependency.get_category() {
                node.add_dep(dep)
            }
        }

        dep_entries.push((plugin.get_category(), node));

        Ok(dep_entries)
    }

    /// Initialize the Plugin Scheduler. This will create a new Plugin Scheduler with the requested
    /// Plugins and its dependencies. Errors will not be returned, but collected and can be
    /// extracted with `get_errors()`. In case of errors the scheduler will still work with errors,
    /// but specific plugins are not scheduled.
    ///
    /// # Arguments
    ///
    /// * `plugin_collection` - A collection of plugins with basic functionality for searching
    /// * `plugins` - A list of plugin IDs to run
    pub fn create<PC, P>(plugin_collection: &PC, plugins: Vec<String>) -> Self
    where
        PC: PluginCollection<P, C>,
        P: Plugin<C>,
        C: Phase + PartialEq + Clone,
    {
        // Hashmap to check if plugin was already added to the scheduler
        let mut entry_map: HashMap<String, Result<C, SchedulerError<C>>> = HashMap::new();

        let mut error_list: Vec<(String, SchedulerError<C>)> = vec![];

        let mut scheduler: GenericArray<Option<DepGraph<String>>, C::LEN> =
            GenericArray::generate(|_| None);
        let mut node_lists: GenericArray<Vec<Node<String>>, C::LEN> =
            GenericArray::generate(|_| vec![]);

        // Fill scheduler with plugins
        for plugin in plugins {
            // Check if plugin is already stored
            if entry_map.contains_key(&plugin) {
                match &entry_map[&plugin] {
                    Err(err) => error_list.push((plugin.clone(), err.clone())),
                    _ => continue,
                }
            }

            // Initialize dependency chain. This is used for error handling
            let mut dependency_chain = vec![(plugin.clone())];

            // Get plugin from collection
            let plugin = match plugin_collection.get_plugin(&plugin) {
                Some(x) => x,
                None => {
                    let error = SchedulerError::PluginNotFound(dependency_chain, plugin.clone());
                    entry_map.insert(plugin.clone(), Err(error.clone()));
                    error_list.push((plugin.clone(), error));
                    continue;
                }
            };

            // Vector to save plugin and all dependencies
            let mut dep_entries: Vec<(C, Node<String>)> = vec![];

            // Collect dependencies of plugins
            match Self::collect_deps(
                plugin_collection,
                &plugin,
                &mut entry_map,
                &mut dependency_chain,
            ) {
                // No errors found, add plugin dependencies to scheduler
                Ok(mut entries) => dep_entries.append(&mut entries),
                // Error found, add plugin and error to scheduler errors
                Err(e) => {
                    error_list.push((plugin.get_id(), e.clone()));
                    entry_map.insert(plugin.get_id(), Err(e));
                    continue;
                }
            }

            // Add plugin and all dependency to the entry map, as well as the node list for the
            // dependency graphs
            for entry in dep_entries {
                // If dependency was already added, just continue
                if entry_map.contains_key(entry.1.id()) {
                    continue;
                }
                // Insert entry to map and node list
                entry_map.insert(entry.1.id().to_owned(), Ok(entry.0.clone()));
                node_lists[entry.0.get()].push(entry.1);
            }
        }

        // After all plugins were checked, create the actual dependency graphs
        for (i, nodes) in node_lists.into_iter().enumerate() {
            let graph = DepGraph::new(&nodes);
            scheduler[i] = Some(graph);
        }

        PluginScheduler {
            dependency_graphs: scheduler,
            errors: error_list,
        }
    }

    /// Get the Errors, collected during the creation. Those errors contain a List of Plugins, that
    /// could not be added to the Scheduler, including a Reason as an SchedulerError.
    pub fn get_errors(&self) -> Vec<(String, SchedulerError<C>)> {
        self.errors.clone()
    }

    /// Execute a phase of the scheduler. This calls the function on every element of the
    /// dependency graph in serial.
    ///
    /// # Arguments
    ///
    /// * `phase` - The phase to execute
    /// * `f` - The function to call
    pub fn execute<F>(&self, phase: C, f: F)
    where
        F: FnMut(String),
    {
        if let Some(plugins) = &self.dependency_graphs[phase.get()] {
            plugins.clone().into_iter().for_each(f);
        }
    }

    /// Execute a phase of the scheduler. This calls the function on every element of the
    /// dependency graph in parallel
    ///
    /// # Arguments
    ///
    /// * `phase` - The phase to execute
    /// * `f` - The function to call
    pub fn execute_parallel<F>(&self, phase: C, f: F)
    where
        F: Fn(Wrapper<String>) + Sync + Send,
    {
        if let Some(plugins) = &self.dependency_graphs[phase.get()] {
            plugins.clone().into_par_iter().for_each(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{marker::PhantomData, vec};

    use generic_array::typenum::U2;

    use crate::{plugin::Phase, scheduler::PluginScheduler};

    use super::{Plugin, PluginCollection};

    #[derive(PartialEq, Clone)]
    enum TestCategory {
        Start,
        Middle,
    }

    impl Phase for TestCategory {
        type LEN = U2;

        fn get(&self) -> usize {
            match self {
                Self::Start => 0,
                Self::Middle => 1,
            }
        }
    }

    #[derive(Clone)]
    struct TestPlugin<C>
    where
        C: Phase + Clone,
    {
        category: C,
        dependencies: Vec<String>,
        name: String,
    }

    impl<C> Plugin<C> for TestPlugin<C>
    where
        C: Phase + Clone,
    {
        fn get_category(&self) -> C {
            self.category.clone()
        }

        fn get_dependencies(&self) -> Vec<String> {
            self.dependencies.clone()
        }

        fn get_id(&self) -> String {
            self.name.clone()
        }
    }

    struct TestPluginCollection<P, C>
    where
        P: Plugin<C>,
        C: Phase,
    {
        plugins: Vec<P>,
        phantom: PhantomData<C>,
    }

    impl<P, C> TestPluginCollection<P, C>
    where
        P: Plugin<C>,
        C: Phase,
    {
        fn new() -> Self {
            TestPluginCollection {
                plugins: Default::default(),
                phantom: Default::default(),
            }
        }

        fn add(&mut self, plugin: P) {
            self.plugins.push(plugin);
        }
    }

    impl<P, C> PluginCollection<P, C> for TestPluginCollection<P, C>
    where
        P: Plugin<C> + Clone,
        C: Phase,
    {
        fn get_plugin(&self, id: &str) -> Option<P> {
            for plugin in &self.plugins {
                if id == plugin.get_id() {
                    return Some(plugin.to_owned());
                }
            }
            None
        }
    }

    #[test]
    fn test_no_error() {
        let mut collection = TestPluginCollection::new();

        collection.add(TestPlugin {
            category: TestCategory::Start,
            dependencies: vec![],
            name: "0".to_string(),
        });

        collection.add(TestPlugin {
            category: TestCategory::Start,
            dependencies: vec!["0".to_string()],
            name: "1".to_string(),
        });

        collection.add(TestPlugin {
            category: TestCategory::Middle,
            dependencies: vec!["1".to_string()],
            name: "2".to_string(),
        });

        let plugin_scheduler =
            PluginScheduler::create(&collection, vec!["0".to_string(), "2".to_string()]);

        assert!(plugin_scheduler.errors.is_empty());
    }

    #[test]
    fn test_error_dependency_cycle() {
        let mut collection = TestPluginCollection::new();

        collection.add(TestPlugin {
            category: TestCategory::Start,
            dependencies: vec!["2".to_string()],
            name: "0".to_string(),
        });

        collection.add(TestPlugin {
            category: TestCategory::Start,
            dependencies: vec!["0".to_string()],
            name: "1".to_string(),
        });

        collection.add(TestPlugin {
            category: TestCategory::Start,
            dependencies: vec!["1".to_string()],
            name: "2".to_string(),
        });

        collection.add(TestPlugin {
            category: TestCategory::Middle,
            dependencies: vec!["1".to_string()],
            name: "3".to_string(),
        });

        collection.add(TestPlugin {
            category: TestCategory::Middle,
            dependencies: vec![],
            name: "4".to_string(),
        });

        let plugin_scheduler = PluginScheduler::create(
            &collection,
            vec!["0".to_string(), "3".to_string(), "4".to_string()],
        );

        assert_eq!(plugin_scheduler.errors.len(), 2);
    }

    #[test]
    fn test_error_not_found() {
        let collection: TestPluginCollection<TestPlugin<TestCategory>, TestCategory> =
            TestPluginCollection::new();

        let plugin_scheduler = PluginScheduler::create(&collection, vec!["0".to_string()]);

        assert_eq!(plugin_scheduler.errors.len(), 1);
    }
}
