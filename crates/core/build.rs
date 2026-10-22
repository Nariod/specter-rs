fn main() {
    // Path-plumbing so the same module is shared by the build script and by
    // the host unit tests (crates/core/src/config.rs includes it under
    // #[cfg(test)]).
    #[path = "build/render.rs"]
    mod render;

    // Re-run when the config or the default profile changes.
    println!("cargo:rerun-if-env-changed=SPT_CONFIG");
    println!("cargo:rerun-if-env-changed=SPT_MANIFEST_OUT");
    println!("cargo:rerun-if-changed=build/render.rs");
    println!("cargo:rerun-if-changed=../../profiles/default.json");
    // The Makefile touches this stamp on every build so the strings manifest
    // is always regenerated even when cargo would otherwise cache the
    // build script (e.g. build/ was wiped but target/ was not).
    println!("cargo:rerun-if-changed=../../build/manifest.stamp");

    // Interface contract with agent_specter (unchanged from the C build in
    // function, changed in format by decision 2026-10-22): the Go plugin
    // writes the per-build config JSON before invoking cargo, exactly as it
    // previously wrote src_beacon/include/Config.h before invoking gcc.
    let json = match std::env::var("SPT_CONFIG") {
        Ok(path) => std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("SPT_CONFIG={path}: cannot read the config file: {e}")),
        Err(_) => render::default_config_json(),
    };

    let gen = render::generate(&json).unwrap_or_else(|e| panic!("invalid beacon config: {e}"));

    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        std::path::Path::new(&out_dir).join("config_gen.rs"),
        gen.rust_source,
    )
    .expect("cannot write config_gen.rs");

    // Strings the blob may legitimately contain (config data). Everything
    // else found by the anti-strings guardrail fails the build. The Makefile
    // routes this to build/config_strings.json via SPT_MANIFEST_OUT.
    let manifest_path = match std::env::var("SPT_MANIFEST_OUT") {
        Ok(p) => std::path::PathBuf::from(p),
        Err(_) => std::path::Path::new(&out_dir).join("config_strings.json"),
    };
    // Beacon runtime literals (not config): strings the beacon legitimately
    // needs at runtime, beyond the malleable profile. Adding one is a
    // conscious act — the anti-strings guardrail fails the build otherwise.
    let mut manifest = gen.strings_manifest;
    manifest.push(".text".to_string()); // find_section's section name probe
    manifest.sort();
    manifest.dedup();
    let manifest = serde_json::to_string(&manifest).expect("manifest serialize");
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent).expect("cannot create the manifest directory");
    }
    std::fs::write(&manifest_path, manifest).expect("cannot write the strings manifest");
}
