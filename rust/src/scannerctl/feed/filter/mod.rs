mod all_builtins;

use all_builtins::ALL_BUILTINS;
use regex::Regex;
use scannerlib::nasl::nasl_std_functions;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use tracing::error;
use walkdir::WalkDir;

use crate::CliError;

#[derive(clap::Parser)]
pub struct FilterArgs {
    feed_path: PathBuf,
}

pub type Builtins<'a> = &'a [String];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Script {
    Runnable,
    NotRunnable,
    Includes(Vec<ScriptPath>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScriptPath(String);

impl ScriptPath {
    fn new(feed_path: &Path, path: &Path) -> Self {
        let relative = pathdiff::diff_paths(path, feed_path).unwrap();
        Self(relative.as_os_str().to_str().unwrap().to_string())
    }
}

impl Script {
    fn new(builtins: Builtins, path: &Path) -> Option<Self> {
        let contents = fs::read_to_string(path);
        match contents {
            Err(e) => {
                error!("Error reading file {path:?}: {e:?}");
                return None;
            }
            Ok(contents) => Some(Script::from_contents(builtins, &contents)),
        }
    }

    pub fn from_contents(builtins: Builtins, contents: &str) -> Self {
        let is_runnable = builtins.iter().all(|builtin| !contents.contains(builtin));
        let includes = get_includes(contents);
        if !is_runnable {
            Self::NotRunnable
        } else if includes.is_empty() {
            Self::Runnable
        } else {
            Self::Includes(includes)
        }
    }

    fn includes(&self) -> impl Iterator<Item = &ScriptPath> {
        if let Self::Includes(includes) = self {
            includes.iter()
        } else {
            panic!("includes() called on non-includes variant")
        }
    }
}

fn get_includes(contents: &str) -> Vec<ScriptPath> {
    let mut includes = vec![];
    for line in contents.lines() {
        if line.contains("include") {
            if let Some(include) = parse_include(line) {
                includes.push(include);
            }
        }
    }
    includes
}

fn parse_include(line: &str) -> Option<ScriptPath> {
    let re = Regex::new(r#"\binclude\("([^"]+)"\)"#).unwrap();
    if let Some(capture) = re.captures_iter(line).next() {
        if let Some(match_) = capture.get(1) {
            return Some(ScriptPath(match_.as_str().to_string()));
        }
    }
    None
}

fn resolve_includes(mut unresolved: HashMap<ScriptPath, Script>) -> HashMap<ScriptPath, Script> {
    let mut resolved: HashMap<ScriptPath, Script> = HashMap::default();
    loop {
        let (newly_resolved, newly_unresolved) = unresolved
            .into_iter()
            .partition::<HashMap<_, _>, _>(|(_, script)| {
                matches!(script, Script::Runnable | Script::NotRunnable)
            });
        unresolved = newly_unresolved;
        let new_length = newly_resolved.len();
        resolved.extend(newly_resolved.into_iter());
        if unresolved.is_empty() {
            return resolved;
        }
        if new_length == 0 {
            panic!("Unresolvable.");
        }
        for v in unresolved.values_mut() {
            let any_not_runnable = v
                .includes()
                .any(|include| matches!(resolved.get(include), Some(Script::NotRunnable)));
            if any_not_runnable {
                *v = Script::NotRunnable;
                continue;
            }
            let all_resolved = v.includes().all(|include| resolved.contains_key(include));
            if !all_resolved {
                continue;
            }
            *v = Script::Runnable;
        }
    }
}

fn get_unimplemented_builtins() -> Vec<String> {
    let exec = nasl_std_functions();
    let implemented: Vec<_> = exec.iter().collect();
    let mut unimplemented: HashSet<_> = ALL_BUILTINS.iter().map(|x| x.to_string()).collect();
    for f in implemented {
        unimplemented.remove(f);
    }
    unimplemented.into_iter().collect()
}

pub fn run(args: FilterArgs) -> Result<(), CliError> {
    let mut scripts = HashMap::new();
    let builtins = get_unimplemented_builtins();
    for entry in WalkDir::new(&args.feed_path).into_iter() {
        let entry = entry.unwrap();
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(script) = Script::new(&builtins, path) {
                let script_path = ScriptPath::new(&args.feed_path, path);
                scripts.insert(script_path, script);
            }
        }
    }
    let resolved = resolve_includes(scripts);
    for (path, script) in resolved.into_iter() {
        if matches!(script, Script::Runnable) {
            println!("{:?}", &path.0);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::feed::filter::{resolve_includes, ScriptPath};

    use super::Script;
    use super::Script::*;

    fn path(path_str: &str) -> ScriptPath {
        ScriptPath(path_str.to_string())
    }

    fn includes(paths: &[&str]) -> Script {
        Includes(paths.into_iter().map(|p| path(p)).collect())
    }

    fn make_scripts(scripts: &[(&str, Script)]) -> HashMap<ScriptPath, Script> {
        scripts
            .into_iter()
            .map(|(name, script)| (ScriptPath(name.to_string()), script.clone()))
            .collect()
    }

    #[test]
    fn resolution() {
        let scripts = [
            ("a", Runnable),
            ("b", Runnable),
            ("c", NotRunnable),
            ("d", includes(&["a", "b", "c"])),
        ];
        let resolved = resolve_includes(make_scripts(&scripts));
        assert_eq!(resolved[&path("a")], Runnable);
        assert_eq!(resolved[&path("b")], Runnable);
        assert_eq!(resolved[&path("c")], NotRunnable);
        assert_eq!(resolved[&path("d")], NotRunnable);
    }

    #[test]
    fn transitive_resolution() {
        let scripts = [
            ("a1", Runnable),
            ("b1", Includes(vec![path("a1")])),
            ("c1", Includes(vec![path("b1")])),
            ("d1", Includes(vec![path("c1")])),
            ("a2", NotRunnable),
            ("b2", Includes(vec![path("a2")])),
            ("c2", Includes(vec![path("b2")])),
            ("d2", Includes(vec![path("c2")])),
        ];
        let resolved = resolve_includes(make_scripts(&scripts));
        assert_eq!(resolved[&path("a1")], Runnable);
        assert_eq!(resolved[&path("b1")], Runnable);
        assert_eq!(resolved[&path("c1")], Runnable);
        assert_eq!(resolved[&path("d1")], Runnable);
        assert_eq!(resolved[&path("a2")], NotRunnable);
        assert_eq!(resolved[&path("b2")], NotRunnable);
        assert_eq!(resolved[&path("c2")], NotRunnable);
        assert_eq!(resolved[&path("d2")], NotRunnable);
    }
}
