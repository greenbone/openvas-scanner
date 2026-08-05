use vergen_git2::{Emitter, Git2};

fn set_version() {
    if let Some(bv) = std::option_env!("BIN_VERSION") {
        println!("cargo:rustc-env=VERGEN_GIT_DESCRIBE={}", bv);
    } else {
        let git2 = Git2::builder().describe(true, false, None).build();
        if let Ok(g) = Emitter::default().add_instructions(&git2)
            && g.emit().is_err()
        {
            // fall back if emit can not generate the env variable
            println!("cargo:rustc-env=VERGEN_GIT_DESCRIBE=unknown");
        }
    }
}

fn main() {
    set_version();
}
