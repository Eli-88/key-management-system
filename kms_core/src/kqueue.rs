use std::ffi::c_void;

pub const EVFILT_READ: i32 = -1;
pub const EV_ADD: i32 = 0x0001;
pub const EV_ONESHOT: i32 = 0x0010;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct KEvent {
    pub ident: usize,           // Identifier for this event (usually a file descriptor)
    pub filter: i16,            // Filter for event (EVFILT_READ, EVFILT_WRITE, etc.)
    pub flags: u16,             // General flags (EV_ADD, EV_ENABLE, etc.)
    pub fflags: u32,            // Filter-specific flags
    pub data: isize,            // Filter-specific data
    pub udata: *const c_void,   // Opaque user data identifier
}


pub struct Kqueue
{
    kq: i32,
}

impl Kqueue {
    pub fn new() -> Kqueue { unsafe { Kqueue { kq: poller() } } }
    pub fn ctl(&self,  fd: i32, filter: i32, flags: i32) -> i32 { unsafe { poll_ctl(self.kq, fd, filter, flags) } }
    pub fn wait(&self, output_events: &mut [KEvent], timeout: i32) -> i32 {
        let max_event = output_events.len() as i32;
        unsafe { poll_wait(self.kq, output_events.as_mut_ptr(), max_event, timeout) }
    }
}

unsafe extern "C" {
    pub fn poller() -> i32;
    pub fn poll_ctl(kq: i32, fd: i32, filter: i32, flags: i32) -> i32;
    pub fn poll_wait(kq: i32, output_events: *mut KEvent, max_event: i32, timeout: i32) -> i32;
}