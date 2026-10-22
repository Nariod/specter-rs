// Integration harness: drives the specter-rs agent plugin exactly the way
// AdaptixC2's ExAgentGenerate does (core/extender/ex_agent.go, v1.2):
//
//	agentProfile, err := module.GenerateProfiles(generateConfig)
//	return module.BuildPayload(generateConfig, agentProfile)
//
// so a passing run proves the full teamserver path: dialog JSON -> SPT_CONFIG
// -> cargo/rust-lld pipeline -> PIC blob. No UI and no client needed.
package main

import (
	"fmt"
	"os"

	"github.com/Adaptix-Framework/axc2"
)

const agentConfig = `{
  "format":     "Bin (raw PIC blob)",
  "sleep":      "1h 2m 5s",
  "jitter":     10,
  "is_killdate": true,
  "kill_date":  "01.01.2030",
  "kill_time":  "00:00:00",
  "debug":      false
}`

const listenerProfile = `{"l_name":"BeaconHTTP","l_bind_host":"0.0.0.0","l_bind_port":"8080"}`

func fatal(format string, args ...any) {
	fmt.Printf("[INT] FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func main() {
	moduleDir, err := os.Getwd()
	if err != nil {
		fatal("cwd: %v", err)
	}

	// InitPlugin(ts=nil, moduleDir, watermark) — same signature the team
	// server looks up via plugin.Open/Lookup.
	agent := InitPlugin(nil, moduleDir, "5b3c7e21")

	buildProfile := adaptix.BuildProfile{
		BuilderId:   "integration-test",
		AgentConfig: agentConfig,
		ListenerProfiles: []adaptix.TransportProfile{
			{Watermark: "deadbeef", Profile: []byte(listenerProfile)},
		},
	}

	fmt.Println("[INT] GenerateProfiles (dialog -> embedded malleable profile)")
	agentProfiles, err := agent.GenerateProfiles(buildProfile)
	if err != nil {
		fatal("GenerateProfiles: %v", err)
	}
	if len(agentProfiles) != 1 {
		fatal("expected 1 agent profile, got %d", len(agentProfiles))
	}

	fmt.Println("[INT] BuildPayload (SPT_CONFIG JSON -> cargo -> rust-lld -> blob)")
	payload, format, err := agent.BuildPayload(buildProfile, agentProfiles)
	if err != nil {
		fatal("BuildPayload: %v", err)
	}
	fmt.Printf("[INT] format=%s size=%d bytes\n", format, len(payload))

	// The blob must start with the SptEntry prologue (sub rsp,8 ; call) and
	// end with the .sptend magic (tools/pe_blob.py checks the same in CI).
	prologue := []byte{0x48, 0x83, 0xEC, 0x08, 0xE8}
	if len(payload) < len(prologue)+8 {
		fatal("blob too small: %d", len(payload))
	}
	for i, b := range prologue {
		if payload[i] != b {
			fatal("blob prologue byte %d: got %#x, want %#x", i, payload[i], b)
		}
	}
	magic := []byte{0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0}
	for i := 0; i < len(magic); i++ {
		if payload[len(payload)-len(magic)+i] != magic[i] {
			fatal("blob end magic mismatch")
		}
	}

	fmt.Printf("[INT] OK: %d-byte PIC blob, prologue and SPT_END magic verified\n", len(payload))
}
