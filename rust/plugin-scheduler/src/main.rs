use std::marker::PhantomData;

use dep_graph::Wrapper;
use generic_array::typenum::U3;
use plugin_scheduler::{
    plugin::{Phase, Plugin, PluginCollection},
    scheduler::PluginScheduler,
};

fn main() {
    let mut collection = TestPluginCollection::new();

    collection.add(TestPlugin {
        category: TestCategory::End,
        dependencies: vec!["4".to_string(), "5".to_string()],
        name: "1".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::End,
        dependencies: vec!["5".to_string(), "6".to_string()],
        name: "2".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Middle,
        dependencies: vec!["7".to_string()],
        name: "3".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::End,
        dependencies: vec!["8".to_string(), "9".to_string()],
        name: "4".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::End,
        dependencies: vec!["9".to_string(), "13".to_string()],
        name: "5".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Middle,
        dependencies: vec!["9".to_string()],
        name: "6".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Middle,
        dependencies: vec!["9".to_string()],
        name: "7".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::End,
        dependencies: vec![],
        name: "8".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Middle,
        dependencies: vec!["13".to_string(), "12".to_string()],
        name: "9".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Middle,
        dependencies: vec![],
        name: "10".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Start,
        dependencies: vec!["12".to_string()],
        name: "11".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Start,
        dependencies: vec![],
        name: "12".to_string(),
    });

    collection.add(TestPlugin {
        category: TestCategory::Start,
        dependencies: vec![],
        name: "13".to_string(),
    });

    let plugin_scheduler = PluginScheduler::create(
        &collection,
        vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "10".to_string(),
            "11".to_string(),
        ],
    );
    println!("Execute Phase Start");
    plugin_scheduler.execute_parallel(TestCategory::Start, run);
    println!();
    println!("Execute Phase Middle");
    plugin_scheduler.execute_parallel(TestCategory::Middle, run);
    println!();
    println!("Execute Phase End");
    plugin_scheduler.execute_parallel(TestCategory::End, run);
    println!();
}

fn run(id: Wrapper<String>) {
    println!("{}", id.to_string());
}

#[derive(PartialEq, Clone)]
enum TestCategory {
    Start,
    Middle,
    End,
}

impl Phase for TestCategory {
    type LEN = U3;

    fn get(&self) -> usize {
        match self {
            Self::Start => 0,
            Self::Middle => 1,
            Self::End => 2,
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
            phantom: PhantomData,
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
