use std::path::PathBuf;

fn main() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Read protocol XML from the system (installed by wayland-protocols)
    let xml = PathBuf::from("/usr/share/wayland-protocols/staging/security-context/security-context-v1.xml");

    // 1. Generate C code from protocol XML
    let gen_c = out.join("security-context-v1.c");
    let gen_h = out.join("security-context-v1.h");

    run("wayland-scanner", ["private-code", &xml.to_string_lossy(), &gen_c.to_string_lossy()]);
    run("wayland-scanner", ["client-header", &xml.to_string_lossy(), &gen_h.to_string_lossy()]);

    // 2. Compile the generated C into a static lib
    let cc = std::env::var("CC").unwrap_or_else(|_| "gcc".to_string());
    let obj = out.join("security-context-v1.o");
    run(&cc, ["-c", "-fPIC", &gen_c.to_string_lossy(), "-o", &obj.to_string_lossy()]);
    run("ar", ["crs",
        &out.join("libsecurity-context-v1.a").to_string_lossy(),
        &obj.to_string_lossy(),
    ]);

    // 3. Write wrapper.h into OUT_DIR for bindgen
    let wrapper = out.join("wrapper.h");
    std::fs::write(
        &wrapper,
        b"#include <wayland-client-core.h>\n#include <wayland-client-protocol.h>\n#include \"security-context-v1.h\"\n",
    ).expect("write wrapper.h");

    // 4. Generate Rust FFI bindings with bindgen
    let bindings = bindgen::Builder::default()
        .header(wrapper.to_string_lossy())
        .clang_arg(format!("-I{}", out.display()))
        .blocklist_item("FP_NAN")
        .blocklist_item("FP_INFINITE")
        .blocklist_item("FP_ZERO")
        .blocklist_item("FP_SUBNORMAL")
        .blocklist_item("FP_NORMAL")
        .generate()
        .expect("bindgen failed");

    bindings.write_to_file(out.join("bindings.rs"))
        .expect("write bindings failed");

    // 5. Linker directives
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=security-context-v1");
    println!("cargo:rustc-link-lib=wayland-client");
    println!("cargo:rerun-if-changed={}", xml.display());
}

fn run<'a>(cmd: &str, args: impl AsRef<[&'a str]>) {
    let status = std::process::Command::new(cmd)
        .args(args.as_ref())
        .status()
        .unwrap_or_else(|_| panic!("failed to run: {cmd}"));
    assert!(status.success(), "{cmd} failed");
}
