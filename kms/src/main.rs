mod key_storage;
mod storage_traits;
mod message;
mod handler;

use crate::handler::on_message;
use crate::key_storage::KeyStorage;
use crate::storage_traits::IStorage;
use kms_core::kqueue::*;
use kms_core::socket::*;
use std::fmt::Debug;
use std::ptr::null_mut;

fn run_server<T>(host: &str, port: u16, mut storage: T) where T: IStorage {
    let server_socket = TcpSocket::new();
    server_socket.socket_option(SOL_SOCKET, SO_REUSEADDR, 1);
    server_socket.bind(host, port);
    server_socket.listen(1024);

    let kq = Kqueue::new();
    kq.ctl(server_socket.fd, EVFILT_READ, EV_ADD);

    let mut recv_buffer: [u8; 1024] = [0; 1024];
    let mut events: [KEvent; 32] = [KEvent{
        ident: 0,
        filter: 0,
        flags: 0,
        fflags: 0,
        data: 0,
        udata: null_mut(),
    }; 32];
    loop {
        let event_count = kq.wait(&mut events, -1);
        if event_count < 0 {
            println!("kqueue poll error"); // let's just log for now, it might be interrupted
            continue;
        }

        for i in 0..event_count as usize {
            let fd = events[i].ident as i32;

            if server_socket.fd == fd {
                let conn = server_socket.accept();
                kq.ctl(conn, EVFILT_READ, EV_ADD | EV_ONESHOT);
            }
            else {
                let conn = TcpSocket::from(fd);
                let byte_recv = conn.recv(&mut recv_buffer);


                if byte_recv > 0 {
                    let response = on_message(&mut storage, &recv_buffer[0..byte_recv as usize]);
                    conn.send(response.as_bytes());
                }

                conn.close();
            }
        }
    }
}

fn main() {
    run_server("127.0.0.1", 8080, KeyStorage::new());
}
