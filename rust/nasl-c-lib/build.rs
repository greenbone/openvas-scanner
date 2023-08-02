fn main() {
    cc::Build::new()
        .file("c/cryptographic/gcrypt_mac.c")
        .file("c/cryptographic/gcrypt_error.c")
        .compile("crypt");

    println!("cargo:rerun-if-changed=c/cryptographic/gcrypt_mac.h");
    println!("cargo:rerun-if-changed=c/cryptographic/gcrypt_error.h");
    println!("cargo:rustc-link-lib=gcrypt");
}
