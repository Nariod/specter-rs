// Specter-rs agent plugin for AdaptixC2 v1.2 (axc2 v1.2.0).
//
// Hybrid architecture (docs/ETUDE-DE-FAISABILITE.md §2): the beacon is the
// Rust rewrite, this plugin is the server-side build entry — the equivalent
// of specter's agent_specter, against the AdaptixC2 1.2 plugin ABI (the
// original specter targets 2.0).
//
// The single interface point with the beacon is the SPT_CONFIG JSON
// contract (decision 2026-10-22): BuildPayload writes the per-build config
// (AES key, sleep/jitter, watermark, kill epoch, malleable profile v2) and
// drives the beacon's own pipeline (make → cargo → rust-lld → blob).
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Adaptix-Framework/axc2"
)

var (
	ModuleDir     string
	AgentWatermark string
)

type PluginAgent struct{}

type ExtenderAgent struct{}

func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark
	return &PluginAgent{}
}

func (p *PluginAgent) GetExtender() adaptix.ExtenderAgent {
	return &ExtenderAgent{}
}

// GenerateConfig: the generation dialog fields (keys = container.put names
// in ax_config.axs).
type GenerateConfig struct {
	Format     string `json:"format"`
	Sleep      string `json:"sleep"`
	Jitter     int    `json:"jitter"`
	IsKillDate bool   `json:"is_killdate"`
	KillDate   string `json:"kill_date"`
	KillTime   string `json:"kill_time"`
	Debug      bool   `json:"debug"`
}

// sptConfig: the beacon build contract (crates/core/build.rs).
type sptConfig struct {
	AESKey    string          `json:"aes_key"`
	SleepMS   int             `json:"sleep_ms"`
	JitterMS  int             `json:"jitter_ms"`
	Watermark uint32          `json:"watermark"`
	KillEpoch int64           `json:"kill_epoch"`
	Profile   json.RawMessage `json:"profile"`
}

// parseDurationMS parses "30s" / "1h 2m 5s" style sleep values.
func parseDurationMS(s string) (int, error) {
	total := 0
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, errors.New("empty sleep value")
	}
	for _, f := range fields {
		unit := f[len(f)-1]
		num, err := strconv.Atoi(f[:len(f)-1])
		if err != nil || num < 0 {
			return 0, fmt.Errorf("invalid sleep field %q", f)
		}
		switch unit {
		case 'h':
			total += num * 3600_000
		case 'm':
			total += num * 60_000
		case 's':
			total += num * 1000
		default:
			return 0, fmt.Errorf("invalid sleep unit in %q (use h/m/s)", f)
		}
	}
	return total, nil
}

// beaconRepo returns the specter-rs checkout used for the build. The team
// server controls it with SPECTER_RS_DIR; the default covers the dev setup.
func beaconRepo() string {
	if dir := os.Getenv("SPECTER_RS_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Documents", "specter-rs")
}

// malleableProfile reads the malleable profile v2 shipped next to the
// plugin. Hosts wiring per-listener comes with the phase 3 transport.
func malleableProfile() (json.RawMessage, error) {
	path := filepath.Join(ModuleDir, "profile_default.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("malleable profile: %w", err)
	}
	return json.RawMessage(data), nil
}

// GenerateProfiles: one embedded profile per listener profile (v1.2 calls
// this before BuildPayload; multi_listeners is false in config.yaml).
func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	var generateConfig GenerateConfig
	if err := json.Unmarshal([]byte(profile.AgentConfig), &generateConfig); err != nil {
		return nil, err
	}
	if _, err := parseDurationMS(generateConfig.Sleep); err != nil {
		return nil, err
	}
	mp, err := malleableProfile()
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(profile.ListenerProfiles))
	for range profile.ListenerProfiles {
		out = append(out, mp)
	}
	return out, nil
}

// BuildPayload: compose the SPT_CONFIG JSON and drive the beacon pipeline.
func (p *PluginAgent) BuildPayload(profile adaptix.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	if len(profile.ListenerProfiles) != 1 || len(agentProfiles) != 1 {
		return nil, "", errors.New("specter-rs builds against exactly one listener")
	}

	var generateConfig GenerateConfig
	if err := json.Unmarshal([]byte(profile.AgentConfig), &generateConfig); err != nil {
		return nil, "", err
	}

	sleepMS, err := parseDurationMS(generateConfig.Sleep)
	if err != nil {
		return nil, "", err
	}
	// Dialog jitter is a percentage (beacon convention); the beacon's jitter
	// is symmetric +/- ms (docs/PARITE.md, documented assumption).
	jitterMS := sleepMS * generateConfig.Jitter / 100

	watermark, err := strconv.ParseUint(AgentWatermark, 16, 32)
	if err != nil {
		return nil, "", fmt.Errorf("watermark %q: %w", AgentWatermark, err)
	}

	var killEpoch int64
	if generateConfig.IsKillDate {
		dt := generateConfig.KillDate + " " + generateConfig.KillTime
		t, err := time.Parse("02.01.2006 15:04:05", dt)
		if err != nil {
			return nil, "", errors.New("invalid killdate, use dd.MM.yyyy + HH:mm:ss")
		}
		killEpoch = t.Unix()
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, "", err
	}

	cfg := sptConfig{
		AESKey:    hex.EncodeToString(key),
		SleepMS:   sleepMS,
		JitterMS:  jitterMS,
		Watermark: uint32(watermark),
		KillEpoch: killEpoch,
		Profile:   agentProfiles[0],
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, "", err
	}

	tmp, err := os.CreateTemp("", "specter-rs-config-*.json")
	if err != nil {
		return nil, "", err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(cfgJSON); err != nil {
		tmp.Close()
		return nil, "", err
	}
	tmp.Close()

	repo := beaconRepo()
	if repo == "" {
		return nil, "", errors.New("SPECTER_RS_DIR not set and no home directory")
	}

	cmd := exec.Command("make", "-C", repo, "blob")
	cmd.Env = append(os.Environ(), "SPT_CONFIG="+tmpPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, "", fmt.Errorf("beacon build failed: %v\n%s", err, string(out))
	}

	blob, err := os.ReadFile(filepath.Join(repo, "build", "beacon.x64.bin"))
	if err != nil {
		return nil, "", fmt.Errorf("beacon blob not found after build: %w", err)
	}
	return blob, "bin", nil
}

// CreateAgent: reached when a beacon checks in — the wire/transport lands in
// phase 3, so no check-in can be processed yet.
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	return adaptix.AgentData{}, nil, errors.New("specter-rs check-in processing lands with the phase 3 transport")
}

// --- ExtenderAgent: stubs until the wire protocol exists (phase 3). ---

func (e *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	return nil, errors.New("specter-rs wire protocol is not implemented yet")
}

func (e *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	return nil, errors.New("specter-rs wire protocol is not implemented yet")
}

func (e *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	return nil, errors.New("specter-rs wire protocol is not implemented yet")
}

func (e *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	return adaptix.TaskData{}, errors.New("specter-rs wire protocol is not implemented yet")
}

func (e *ExtenderAgent) CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	return adaptix.TaskData{}, adaptix.ConsoleMessageData{}, errors.New("specter-rs commands land with the phase 3 wire")
}

func (e *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	return errors.New("specter-rs wire protocol is not implemented yet")
}

func (e *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{}
}

func (e *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{}
}
