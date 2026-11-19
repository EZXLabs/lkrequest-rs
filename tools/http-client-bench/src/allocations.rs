use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use serde::Serialize;

struct CountingAllocator;

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
static ENABLED: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static REQUESTED_BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(&ALLOCATIONS, layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(&ALLOCATIONS, layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(&REALLOCATIONS, new_size);
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn record(counter: &AtomicU64, size: usize) {
    if ENABLED.load(Ordering::Relaxed) {
        counter.fetch_add(1, Ordering::Relaxed);
        REQUESTED_BYTES.fetch_add(size as u64, Ordering::Relaxed);
    }
}

#[derive(Debug, Serialize)]
pub struct AllocationSummary {
    pub allocation_calls: u64,
    pub reallocation_calls: u64,
    pub requested_bytes: u64,
}

pub struct Measurement(bool);

impl Measurement {
    pub fn start(enabled: bool) -> Self {
        if enabled {
            ALLOCATIONS.store(0, Ordering::Relaxed);
            REALLOCATIONS.store(0, Ordering::Relaxed);
            REQUESTED_BYTES.store(0, Ordering::Relaxed);
            ENABLED.store(true, Ordering::Relaxed);
        }
        Self(enabled)
    }

    pub fn finish(self) -> Option<AllocationSummary> {
        ENABLED.store(false, Ordering::Relaxed);
        self.0.then(|| AllocationSummary {
            allocation_calls: ALLOCATIONS.load(Ordering::Relaxed),
            reallocation_calls: REALLOCATIONS.load(Ordering::Relaxed),
            requested_bytes: REQUESTED_BYTES.load(Ordering::Relaxed),
        })
    }
}

impl Drop for Measurement {
    fn drop(&mut self) {
        ENABLED.store(false, Ordering::Relaxed);
    }
}
