// Interface contract with agent_specter — unchanged from the C build:
// the Go plugin writes the per-build configuration (AES key, sleep, jitter,
// watermark, C2 hosts, malleable profile) before invoking the build, exactly
// as it previously wrote src_beacon/include/Config.h before invoking gcc.
// This script will read it (path from SPT_CONFIG) and generate the config
// module. See docs/ETUDE-DE-FAISABILITE.md, sections 2 and 8 (phase 1).
fn main() {
    println!("cargo:rerun-if-env-changed=SPT_CONFIG");
    println!("cargo:rerun-if-changed=Linker.ld");
}
