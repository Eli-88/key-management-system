pub const SOL_SOCKET: i32 = 0xffff;
pub const SO_REUSEADDR: i32 = 0x0004;

pub struct TcpSocket
{
    pub fd: i32,
}

impl From<i32> for TcpSocket {
    fn from(fd: i32) -> TcpSocket { TcpSocket { fd } }
}

impl TcpSocket
{
    pub fn new() -> TcpSocket { unsafe { TcpSocket { fd: tcp_socket() } } }
    pub fn close(&self) -> i32 { unsafe { tcp_close(self.fd) } }
    pub fn listen(&self, backlog: i32) -> i32 { unsafe { tcp_listen(self.fd, backlog) } }
    pub fn bind(&self, host: &str, port: u16) -> i32 {
        unsafe { tcp_bind(self.fd, host.as_ptr(), host.len() as i16, port) }
    }
    pub fn accept(&self) -> i32 { unsafe { tcp_accept(self.fd) } }
    pub fn accept_with_remote_address(&self) -> (i32, Vec<u8>, u16) {
        let mut host: [u8; 16] = [0; 16];
        let mut port: u16 = 0;
        let mut host_len: u16 = 0;
        unsafe {
            let conn = tcp_accept_with_remote_address(self.fd, host.as_mut_ptr(), 16, &mut port, &mut host_len);
            (conn, host[..host_len as usize].to_vec(), port)
        }
    }
    pub fn recv(&self, buffer: &mut [u8]) -> i32 {
        let len = buffer.len() as i32;
        unsafe { tcp_recv(self.fd, buffer.as_mut_ptr(), len) }
    }
    pub fn send(&self, buffer: &[u8]) -> i32 { unsafe { tcp_send(self.fd, buffer.as_ptr(), buffer.len() as i32) } }
    pub fn shutdown(&self) -> i32 { unsafe { tcp_shutdown(self.fd) } }
    pub fn socket_option(&self, level: i32, option_name: i32, flag: i32) -> i32 { unsafe { set_socket_option(self.fd, level, option_name, flag) } }
}



unsafe extern "C" {
    pub fn tcp_socket() -> i32;
    pub fn tcp_close(fd: i32) -> i32;
    pub fn tcp_listen(fd: i32, backlog: i32) -> i32;
    pub fn tcp_bind(fd: i32, host: *const u8, host_len: i16, port: u16) -> i32;
    pub fn tcp_accept(fd: i32) -> i32;
    pub fn tcp_accept_with_remote_address(fd: i32, remote_host: *mut u8, remote_host_input_len: i32, remote_port: &mut u16, remote_host_output_len: &mut u16) -> i32;
    pub fn tcp_recv(fd: i32, buffer: *mut u8, len: i32) -> i32;
    pub fn tcp_send(fd: i32, buffer: *const u8, len: i32) -> i32;
    pub fn tcp_shutdown(fd: i32) -> i32;
    pub fn set_socket_option(fd: i32, level: i32, option_name: i32, flag: i32) -> i32;
}