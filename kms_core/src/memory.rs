use std::ffi::c_void;

pub const PROT_NONE: i32 =  0x00;                           /* [MC2] no permissions */
pub const PROT_READ: i32 =  0x01;                           /* [MC2] pages can be read */
pub const PROT_WRITE: i32 = 0x02;                           /* [MC2] pages can be written */
pub const PROT_EXEC: i32 =  0x04;                           /* [MC2] pages can be executed */
pub const MAP_PRIVATE: i32 = 0x0002;                        /* [MF|SHM] changes are private */
pub const MAP_ANONYMOUS: i32 = 0x1000;                      /* allocated from memory, swap space */
pub const MAP_FAILED: *mut c_void = -1isize as *mut c_void; /* [MF|SHM] mmap failed */

unsafe extern "C" {
    pub fn memory_map(address: *mut c_void, size: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> *mut c_void;
    pub fn memory_unmap(address: *const c_void, size: usize) -> i32;
}