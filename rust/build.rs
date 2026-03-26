use std::{
    fmt::Display,
    fs::{self, File},
    io::BufWriter,
    path::Path,
};

use flate2::{Compression, write::GzEncoder};
use tar::Builder;
use vergen_git2::{Emitter, Git2Builder};

fn create_test_layer(name: &str) -> Option<()> {
    fn ignore_error<O, E>(input: Result<O, E>) -> Option<O>
    where
        E: Display,
    {
        match input {
            Ok(x) => Some(x),
            Err(e) => {
                println!("cargo:warning={e}: Some tests may fail due to missing layer.");
                None
            }
        }
    }

    let input_dir = format!("test-data/images/{name}");
    let input_dir = Path::new(&input_dir);
    let output = format!("test-data/layers/{name}.tar.gz");
    let output_path = Path::new(&output);

    if !output_path.exists() {
        println!("cargo:info=Creating {output}");

        if let Some(parent_dir) = output_path.parent() {
            ignore_error(fs::create_dir_all(parent_dir))?;
        }
        let tar_gz = ignore_error(File::create(output_path))?;
        let enc = GzEncoder::new(BufWriter::new(tar_gz), Compression::default());
        let mut tar = Builder::new(enc);
        ignore_error(tar.append_dir_all(".", input_dir))?;
        ignore_error(ignore_error(tar.into_inner())?.finish())?;

        println!("cargo:info=Created {output}.");
    }
    Some(())
}

fn create_test_binaries() {
    create_test_layer("victim");
}

fn set_version() {
    if let Some(bv) = std::option_env!("BIN_VERSION") {
        println!("cargo:rustc-env=VERGEN_GIT_DESCRIBE={}", bv);
    } else if let Ok(git2) = Git2Builder::default().describe(true, false, None).build()
        && let Ok(g) = Emitter::default().add_instructions(&git2)
        && g.emit().is_err()
    {
        // fall back if emit can not generate the env variable
        println!("cargo:rustc-env=VERGEN_GIT_DESCRIBE=unknown");
    }
}

fn main() {
    //println!("cargo:rerun-if-changed=migrations");
    create_test_binaries();
    set_version();
}
