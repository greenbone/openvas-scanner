# feed

Is a specialized crate to handle `feed` related tasks.

A `feed` is a directory of nasl scripts that has at least:
- `sha256sums` - a list of files and sha256sums (usually created by executing sha256sum * > sha256sums) and is used to load the various scripts to be updated.
- `plugin_feed_info.inc` - feed related information that are read in before running the description mode.

A `plugin_feed_info.inc` defines the variables:
```text
PLUGIN_SET = "the version of the feed";
PLUGIN_FEED = "name of the feed";
FEED_VENDOR = "vendor";
FEED_HOME = "url the the feed";
FEED_NAME = "short name of the feed";
```
## Verify

[Implements](./src/verify/mod.rs) a [HashSumNameLoader](./src/verify/mod.rs#L93) that loads the filenames defined in the sha256sums and verifies the corresponding hashsum. 
Also, implements a [signature verifier](./src/verify/mod.rs#L163) for checking the signature of the sha256sums file.

### Example

```no_run
use nasl_interpreter::FSPluginLoader;
// needs to be path that contains a sha256sums file otherwise
// it will throw an exception.
let path = "/var/lib/openvas/plugins/";
let loader = FSPluginLoader::new(path);
let verifier = feed::HashSumNameLoader::sha256(&loader).expect("sha256sums");
```

## Current status

Only feed update is implemented.

It would be great to extend it with:

- Create - to create a feed structure more conveniently 
- Retrieve - to retrieve a feed
- Verify - to check the feed for syntax errors and gpg verification of sha256sums

## Build

Run `cargo test` to test and `cargo build --release` to build it.