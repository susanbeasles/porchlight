//! Compiles the libxpc shim on macOS hosts only. On other hosts the crate's macOS module is
//! still type-checked by `cargo check --target aarch64-apple-darwin`, which does not link.

fn main() {
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=include");
    let target = std::env::var("TARGET").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();
    if !target.contains("apple") {
        return;
    }
    if !host.contains("apple") {
        println!("cargo:warning=pl-xpc: shim not compiled for {target} on {host} (check only)");
        return;
    }
    cc::Build::new()
        .std("c11")
        .flag("-fblocks")
        .include("include")
        .file("csrc/xpc_shim.c")
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("pl_xpc_c");
}
