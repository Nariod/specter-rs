//! Heap allocation via the instance (port of the runtime heap of
//! `src_beacon/src/runtime/`).
//!
//! The beacon has no global allocator (a `#[global_allocator]` would require
//! a `static`, forbidden by the no-globals philosophy): allocation goes
//! through [`Heap`], which holds the process-heap handle and the resolved
//! function pointers. Everything is a plain `extern "system"` signature, so
//! the host unit tests exercise the real logic with mock WinAPI functions.

use core::ffi::c_void;

/// `HeapAlloc` (kernel32).
pub type HeapAllocFn =
    unsafe extern "system" fn(heap: *mut c_void, flags: u32, size: usize) -> *mut c_void;
/// `HeapFree` (kernel32).
pub type HeapFreeFn =
    unsafe extern "system" fn(heap: *mut c_void, flags: u32, ptr: *mut c_void) -> i32;
/// `GetProcessHeap` (kernel32).
pub type GetProcessHeapFn = unsafe extern "system" fn() -> *mut c_void;

/// `HEAP_ZERO_MEMORY`.
pub const HEAP_ZERO_MEMORY: u32 = 0x08;

/// Instance-scoped heap: process-heap handle plus resolved WinAPI pointers.
#[derive(Clone, Copy)]
pub struct Heap {
    pub handle: *mut c_void,
    pub alloc: HeapAllocFn,
    pub free: HeapFreeFn,
}

impl Heap {
    /// Zero-initialized allocation. Returns null on failure, like `HeapAlloc`.
    ///
    /// # Safety
    ///
    /// The pointers must come from a successful bootstrap resolution, and
    /// `size` must not overflow.
    #[inline]
    pub unsafe fn allocate(&self, size: usize) -> *mut u8 {
        (self.alloc)(self.handle, HEAP_ZERO_MEMORY, size) as *mut u8
    }

    /// Free a pointer returned by [`Heap::allocate`]. Null is ignored.
    ///
    /// # Safety
    ///
    /// The pointer must come from this heap and must not be freed twice.
    #[inline]
    pub unsafe fn deallocate(&self, ptr: *mut u8) {
        if !ptr.is_null() {
            (self.free)(self.handle, 0, ptr as *mut c_void);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::prelude::v1::*;

    thread_local! {
        static CALLS: RefCell<Vec<(usize, bool)>> = RefCell::new(Vec::new());
        static FREED: RefCell<Vec<usize>> = RefCell::new(Vec::new());
    }

    unsafe extern "system" fn mock_alloc(_h: *mut c_void, flags: u32, size: usize) -> *mut c_void {
        CALLS.with(|c| c.borrow_mut().push((size, flags & HEAP_ZERO_MEMORY != 0)));
        // Leaked on purpose: test-only, tiny sizes.
        Box::into_raw(vec![0u8; size.max(1)].into_boxed_slice()) as *mut c_void
    }

    unsafe extern "system" fn mock_free(_h: *mut c_void, _f: u32, ptr: *mut c_void) -> i32 {
        FREED.with(|f| f.borrow_mut().push(ptr as usize));
        1
    }

    fn mock_heap() -> Heap {
        Heap {
            handle: 0x1000 as *mut c_void,
            alloc: mock_alloc,
            free: mock_free,
        }
    }

    #[test]
    fn allocate_passes_handle_flags_and_size() {
        let heap = mock_heap();
        let p = unsafe { heap.allocate(0x40) };
        assert!(!p.is_null());
        CALLS.with(|c| assert_eq!(c.borrow().last(), Some(&(0x40, true))));
        unsafe {
            heap.deallocate(p);
        }
        FREED.with(|f| assert_eq!(f.borrow().last(), Some(&(p as usize))));
    }

    #[test]
    fn deallocate_ignores_null() {
        let heap = mock_heap();
        let before = FREED.with(|f| f.borrow().len());
        unsafe { heap.deallocate(core::ptr::null_mut()) };
        FREED.with(|f| assert_eq!(f.borrow().len(), before));
    }
}
