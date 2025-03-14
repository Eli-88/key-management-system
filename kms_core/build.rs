extern crate cc;

fn main() {
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rerun-if-changed=build.rs");

    cc::Build::new()
        .file("src/kms_core.c")
        .compile("kms_core")
}