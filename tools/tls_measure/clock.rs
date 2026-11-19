//! Test-tool clocks only. Wall time and scheduled thread CPU are distinct.
//! Includes clock-call overhead; compare identical harnesses and retain raw
//! samples. Windows CPU accounting can be coarser than its 100 ns units.

use std::time::Instant;

pub struct ClockStart {
    wall: Instant,
    cpu: Option<u64>,
}

pub struct Elapsed {
    pub wall_ns: u128,
    pub thread_cpu_ns: Option<u64>,
}

impl ClockStart {
    pub fn start() -> Self {
        let cpu = thread_cpu_ns();
        Self {
            wall: Instant::now(),
            cpu,
        }
    }

    pub fn elapsed(self) -> Elapsed {
        let cpu = thread_cpu_ns();
        Elapsed {
            wall_ns: self.wall.elapsed().as_nanos(),
            thread_cpu_ns: self
                .cpu
                .zip(cpu)
                .and_then(|(start, end)| end.checked_sub(start)),
        }
    }
}

#[cfg(windows)]
pub const THREAD_CPU_CLOCK: &str = "GetThreadTimes; 100 ns units, OS accounting resolution";
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub const THREAD_CPU_CLOCK: &str = "clock_gettime(CLOCK_THREAD_CPUTIME_ID)";
#[cfg(not(any(windows, all(target_os = "linux", target_pointer_width = "64"))))]
pub const THREAD_CPU_CLOCK: &str = "unavailable; thread_cpu_ns is null";

#[cfg(windows)]
fn thread_cpu_ns() -> Option<u64> {
    use std::ffi::c_void;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThread() -> *mut c_void;
        fn GetThreadTimes(
            thread: *mut c_void,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
    }

    let mut creation = FileTime::default();
    let mut exit = FileTime::default();
    let mut kernel = FileTime::default();
    let mut user = FileTime::default();
    // The pseudo-handle refers to this thread and requires no close operation.
    // All four writable FILETIME values live through the synchronous call.
    let ok = unsafe {
        GetThreadTimes(
            GetCurrentThread(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return None;
    }
    let ticks = |value: FileTime| (u64::from(value.high) << 32) | u64::from(value.low);
    ticks(kernel).checked_add(ticks(user))?.checked_mul(100)
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn thread_cpu_ns() -> Option<u64> {
    use std::ffi::{c_int, c_long};

    #[repr(C)]
    struct Timespec {
        seconds: c_long,
        nanoseconds: c_long,
    }
    extern "C" {
        fn clock_gettime(clock_id: c_int, time: *mut Timespec) -> c_int;
    }
    let mut time = Timespec {
        seconds: 0,
        nanoseconds: 0,
    };
    // Linux's per-thread CPU clock is 3. On 64-bit Linux time_t and long
    // have the same ABI; other Unix/time64 ABIs intentionally return None.
    if unsafe { clock_gettime(3, &mut time) } != 0
        || time.seconds < 0
        || !(0..1_000_000_000).contains(&time.nanoseconds)
    {
        return None;
    }
    (time.seconds as u64)
        .checked_mul(1_000_000_000)?
        .checked_add(time.nanoseconds as u64)
}

#[cfg(not(any(windows, all(target_os = "linux", target_pointer_width = "64"))))]
fn thread_cpu_ns() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clocks_are_available_where_supported_and_never_subtract_backwards() {
        assert!(!THREAD_CPU_CLOCK.is_empty());
        let start = ClockStart::start();
        let mut value = 1u64;
        for _ in 0..50_000 {
            value = std::hint::black_box(value.wrapping_mul(3).wrapping_add(1));
        }
        std::hint::black_box(value);
        let elapsed = start.elapsed();
        assert!(elapsed.wall_ns > 0);
        #[cfg(any(windows, all(target_os = "linux", target_pointer_width = "64")))]
        assert!(elapsed.thread_cpu_ns.is_some());
        #[cfg(not(any(windows, all(target_os = "linux", target_pointer_width = "64"))))]
        assert_eq!(elapsed.thread_cpu_ns, None);
    }
}
