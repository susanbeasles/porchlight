//! Compiles the portable C (ring, layout probe). Skipped when cross-checking an Apple target
//! from a non-Apple host: there is no SDK, and `cargo check` does not link.

fn main() {
    println!("cargo:rerun-if-changed=csrc");
    println!("cargo:rerun-if-changed=include");
    let target = std::env::var("TARGET").unwrap_or_default();
    let host = std::env::var("HOST").unwrap_or_default();
    if target.contains("apple") && !host.contains("apple") {
        println!("cargo:warning=pl-raw: C not compiled for {target} on {host} (check only)");
        return;
    }
    cc::Build::new()
        .std("c11")
        .include("include")
        .file("csrc/ring.c")
        .file("csrc/layout.c")
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true)
        .compile("pl_raw_c");
}
