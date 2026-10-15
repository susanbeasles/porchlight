//! Compiles the ES shim on macOS hosts and links EndpointSecurity. On other hosts the Rust
//! side is still type-checked for the Apple target; nothing is linked.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=csrc");
    // es_copy.c and es_shim.c include rawevent.h and ring.h: a layout change must rebuild.
    println!("cargo:rerun-if-changed=../pl-raw/include");
    let target = std::env::var("TARGET").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();
    if !target.contains("apple") {
        return;
    }
    if !host.contains("apple") {
        println!("cargo:warning=pl-es: shim not compiled for {target} on {host} (check only)");
        return;
    }
    let raw_include = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default())
        .join("../pl-raw/include");
    cc::Build::new()
        .std("c11")
        .flag("-fblocks")
        .include("csrc")
        .include(raw_include)
        .file("csrc/es_copy.c")
        .file("csrc/es_shim.c")
        .file("csrc/es_selftest.c")
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("pl_es_c");
    println!("cargo:rustc-link-lib=EndpointSecurity");
    println!("cargo:rustc-link-lib=bsm");
}
