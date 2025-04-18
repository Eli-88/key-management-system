mod api;
mod handler;
mod interface;
mod key_storage;
mod message;

use crate::interface::{IHandler, IStorage};
use crate::key_storage::KeyStorage;
use handler::HttpHandler;
use kms_core::poller::*;
use kms_core::socket::*;
use std::fmt::Debug;

fn run_server<T, U>(host: &str, port: u16, mut storage: T, handler: U)
where
    T: IStorage,
    U: IHandler<T>,
{
    let server_socket = TcpSocket::new();
    server_socket.socket_option(SOL_SOCKET, SO_REUSEADDR, 1);
    server_socket.bind(host, port);
    server_socket.listen(1024);

    let poller = Poller::new();
    poller.ctl(server_socket.fd, Flags::Read);

    let mut recv_buffer: [u8; 1024] = [0; 1024];

    let mut events: [PollEvent; 32] = [PollEvent { fd: -1 }; 32];
    loop {
        let event_count = poller.wait(&mut events, -1);
        if event_count < 0 {
            println!("poll error"); // let's just log for now, it might be interrupted
            continue;
        }

        for i in 0..event_count as usize {
            let fd = events[i].fd;

            if server_socket.fd == fd {
                let conn = server_socket.accept();
                poller.ctl(conn, Flags::Read);
            } else {
                let conn = TcpSocket::from(fd);
                let byte_recv = conn.recv(&mut recv_buffer);

                if byte_recv > 0 {
                    let response =
                        handler.on_message(&mut storage, &recv_buffer[0..byte_recv as usize]);
                    conn.send(response.as_bytes());
                }

                conn.close();
            }
        }
    }
}

fn main() {
    let mut handler = HttpHandler::new();
    handler.register("/register", api::process_register_request);
    handler.register("/encrypt", api::process_encrypt_request);
    handler.register("/decrypt", api::process_decrypt_request);

    run_server("127.0.0.1", 8080, KeyStorage::new(), handler);
}
