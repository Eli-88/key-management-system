#[cfg(target_os = "macos")]
const EVFILT_READ: i32 = -1;

#[cfg(target_os = "macos")]
const EV_ADD: i32 = 0x0001;

#[cfg(target_os = "macos")]
const EV_ONESHOT: i32 = 0x0010;

#[cfg(target_os = "linux")]
const EPOLL_CTL_ADD: i32 = 1;

#[cfg(target_os = "linux")]

const EPOLLIN: i32 = 0x001;
#[cfg(target_os = "linux")]
const EPOLLONESHOT: i32 = 1 << 30;

pub enum Flags {
    Read,
    ReadOneShot,
}

#[cfg(target_os = "macos")]
fn generate_filter_and_flags(flags: Flags) -> (i32, i32) {
    match flags {
        Flags::Read => (EVFILT_READ, EV_ADD),
        Flags::ReadOneShot => (EVFILT_READ, EV_ADD | EV_ONESHOT),
    }
}

#[cfg(target_os = "linux")]
fn generate_filter_and_flags(flags: Flags) -> (i32, i32) {
    match flags {
        Flags::Read => (EPOLL_CTL_ADD, EPOLLIN),
        Flags::ReadOneShot => (EPOLL_CTL_ADD, EPOLLONESHOT),
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PollEvent {
    pub fd: i32,
}

pub struct Poller {
    kq: i32,
}

impl Poller {
    pub fn new() -> Poller {
        unsafe { Poller { kq: poller() } }
    }
    pub fn ctl(&self, fd: i32, flags: Flags) -> i32 {
        let (filter, flags) = generate_filter_and_flags(flags);
        unsafe { poll_ctl(self.kq, fd, filter, flags) }
    }
    pub fn wait(&self, output_events: &mut [PollEvent], timeout: i32) -> i32 {
        let max_event = output_events.len() as i32;
        unsafe { poll_wait(self.kq, output_events.as_mut_ptr(), max_event, timeout) }
    }
}

unsafe extern "C" {
    pub fn poller() -> i32;
    pub fn poll_ctl(kq: i32, fd: i32, filter: i32, flags: i32) -> i32;
    pub fn poll_wait(kq: i32, output_events: *mut PollEvent, max_event: i32, timeout: i32) -> i32;
}
