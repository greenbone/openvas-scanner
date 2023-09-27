# Plugin Scheduler

## Plugin

A plugin is a simple struct containing an identifier, a list of identifier representing the dependencies and a Category or Phase, in which the plugin should be launched.

## Scheduler

The Scheduler uses a Collection of Plugins and a list of requested plugin identifiers to create an execution order of the requested plugins. It automatically resolves dependencies and detects errors. Plugins or dependencies containing some kind of error are not added to the scheduler, but are collected as errors.


## Usage

Here is a simple example creating a scheduler and executing plugins in parallel:

```rust
use std::{marker::PhantomData, slice::Iter, thread, time};

use generic_array::typenum::U2;
use plugin_scheduler::{
    plugin::{Phase, Plugin, PluginCollection},
    scheduler::PluginScheduler,
};

#[derive(PartialEq, Clone, Debug)]
enum TestCategory {
    Phase1,
    Phase2,
}

impl Phase for TestCategory {
    type LEN = U2;

    fn get(&self) -> usize {
        match self {
            Self::Phase1 => 0,
            Self::Phase2 => 1,
        }
    }
}

impl TestCategory {
    pub fn iterator() -> Iter<'static, TestCategory> {
        static CATEGORIES: [TestCategory; 2] = [TestCategory::Phase1, TestCategory::Phase2];
        CATEGORIES.iter()
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

fn main() {
    let mut collection = TestPluginCollection::new();

    collection.add(TestPlugin {
        category: TestCategory::Phase2,
        dependencies: vec!["1".to_string(), "2".to_string()],
        name: "0".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Phase2,
        dependencies: vec!["2".to_string()],
        name: "1".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Phase1,
        dependencies: vec![],
        name: "2".to_string(),
    });

    let scheduler = PluginScheduler::create(&collection, vec!["0".to_string()]);

    for phase in TestCategory::iterator() {
        scheduler.execute_parallel(phase.to_owned(), |script| todo!());
    }
}
```
