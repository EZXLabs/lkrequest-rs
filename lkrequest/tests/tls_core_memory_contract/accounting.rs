//! Test-only origin accounting. Headers follow allocations across scopes and
//! threads, so an unrelated deallocation cannot reduce the active owner's total.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

const OWNER_LIMIT: usize = 128;

struct Counters {
    live: AtomicUsize,
    peak: AtomicUsize,
    blocks: AtomicUsize,
    allocations: AtomicUsize,
    reallocations: AtomicUsize,
    requested: AtomicUsize,
}

impl Counters {
    const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            blocks: AtomicUsize::new(0),
            allocations: AtomicUsize::new(0),
            reallocations: AtomicUsize::new(0),
            requested: AtomicUsize::new(0),
        }
    }

    fn grow(&self, bytes: usize) {
        let live = self.live.fetch_add(bytes, Relaxed) + bytes;
        self.peak.fetch_max(live, Relaxed);
    }
}

static COUNTERS: [Counters; OWNER_LIMIT] = [const { Counters::new() }; OWNER_LIMIT];
static NEXT_OWNER: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static ACTIVE: Cell<usize> = const { Cell::new(0) };
}

fn allocation_layout(layout: Layout) -> Option<(Layout, usize)> {
    Layout::new::<usize>()
        .extend(layout)
        .ok()
        .map(|(combined, offset)| (combined.pad_to_align(), offset))
}

pub struct Allocator;

// Each raw allocation contains an aligned owner header followed by the original
// payload. Reallocation keeps the original alignment, hence the payload offset.
// No bookkeeping operation allocates, locks, formats, or panics.
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.allocate(layout, false) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.allocate(layout, true) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let Some((combined, offset)) = allocation_layout(layout) else {
            std::process::abort();
        };
        let raw = unsafe { pointer.sub(offset) };
        let owner = unsafe { raw.cast::<usize>().read() };
        if owner != 0 {
            COUNTERS[owner].live.fetch_sub(layout.size(), Relaxed);
            COUNTERS[owner].blocks.fetch_sub(1, Relaxed);
        }
        unsafe { System.dealloc(raw, combined) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let Some((combined, offset)) = allocation_layout(layout) else {
            return std::ptr::null_mut();
        };
        let Some((resized, _)) = Layout::from_size_align(size, layout.align())
            .ok()
            .and_then(allocation_layout)
        else {
            return std::ptr::null_mut();
        };
        let raw = unsafe { pointer.sub(offset) };
        let owner = unsafe { raw.cast::<usize>().read() };
        let result = unsafe { System.realloc(raw, combined, resized.size()) };
        if result.is_null() {
            return result;
        }
        if owner != 0 {
            let counters = &COUNTERS[owner];
            if size >= layout.size() {
                counters.grow(size - layout.size());
            } else {
                counters.live.fetch_sub(layout.size() - size, Relaxed);
            }
            counters.reallocations.fetch_add(1, Relaxed);
            counters.requested.fetch_add(size, Relaxed);
        }
        unsafe { result.add(offset) }
    }
}

impl Allocator {
    unsafe fn allocate(&self, layout: Layout, zeroed: bool) -> *mut u8 {
        let Some((combined, offset)) = allocation_layout(layout) else {
            return std::ptr::null_mut();
        };
        let raw = if zeroed {
            unsafe { System.alloc_zeroed(combined) }
        } else {
            unsafe { System.alloc(combined) }
        };
        if raw.is_null() {
            return raw;
        }
        let owner = ACTIVE.try_with(Cell::get).unwrap_or(0);
        unsafe { raw.cast::<usize>().write(owner) };
        if owner != 0 {
            let counters = &COUNTERS[owner];
            counters.grow(layout.size());
            counters.blocks.fetch_add(1, Relaxed);
            counters.allocations.fetch_add(1, Relaxed);
            counters.requested.fetch_add(layout.size(), Relaxed);
        }
        unsafe { raw.add(offset) }
    }
}

#[derive(Clone, Copy)]
pub struct Owner(usize);

#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    pub live: usize,
    pub peak: usize,
    pub blocks: usize,
    pub allocations: usize,
    pub reallocations: usize,
    pub requested: usize,
}

struct Scope(usize);
impl Drop for Scope {
    fn drop(&mut self) {
        ACTIVE.with(|active| active.set(self.0));
    }
}

impl Owner {
    pub fn new() -> Self {
        let id = NEXT_OWNER.fetch_add(1, Relaxed);
        assert!(id < OWNER_LIMIT, "test owner registry exhausted");
        Self(id)
    }

    pub fn enter<T>(&self, operation: impl FnOnce() -> T) -> T {
        let scope = Scope(ACTIVE.with(|active| active.replace(self.0)));
        let result = operation();
        drop(scope);
        result
    }

    pub fn snapshot(&self) -> Snapshot {
        let counters = &COUNTERS[self.0];
        Snapshot {
            live: counters.live.load(Relaxed),
            peak: counters.peak.load(Relaxed),
            blocks: counters.blocks.load(Relaxed),
            allocations: counters.allocations.load(Relaxed),
            reallocations: counters.reallocations.load(Relaxed),
            requested: counters.requested.load(Relaxed),
        }
    }

    /// Call only between operations, while this owner has no concurrent work.
    pub fn reset_peak(&self) {
        let counters = &COUNTERS[self.0];
        counters.peak.store(counters.live.load(Relaxed), Relaxed);
    }
}
