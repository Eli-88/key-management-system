mod key_storage;
mod storage_traits;
mod message;
mod api;

use crate::key_storage::KeyStorage;
use crate::storage_traits::IStorage;
use kms_core::kqueue::*;
use kms_core::socket::*;
use std::fmt::Debug;
use std::ptr::null_mut;
use std::collections::HashMap;
use httparse::Status;

fn run_server<T>(host: &str, port: u16, mut storage: T) where T: IStorage {
    let handler = HttpHandler::new();

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
                    let response = handler.on_message(&mut storage, &recv_buffer[0..byte_recv as usize]);
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

pub struct HttpHandler<T> where T: IStorage
{
    router: HashMap<String, fn(&mut T, &[u8]) -> Option<String>>,
}

impl <T> HttpHandler<T> where T: IStorage {
    pub fn new() -> Self {
        let mut router: HashMap<String, fn(&mut T, &[u8]) -> Option<String>> = HashMap::new();
        router.insert(String::from("/register"), api::process_register_request);
        router.insert(String::from("/encrypt"), api::process_encrypt_request);
        router.insert(String::from("/decrypt"), api::process_decrypt_request);

        HttpHandler { router }
    }

    pub fn on_message(&self, storage: &mut T, buffer: &[u8]) -> String {
        let mut headers = [httparse::Header { name: "", value: &[] }; 32];
        let mut req = httparse::Request::new(&mut headers);

        let mut response: Option<String> = None;
        match req.parse(&buffer) {
            Ok(Status::Complete(sz)) => {
                match req.path {
                    Some(path) => {
                        match self.router.get(path) {
                            Some(ops) => {
                                response = ops(storage, &buffer[sz..])
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        match response {
            Some(response) => {
                format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     \r\n\
                     {}",
                    response.len(),
                    response
                )
            }
            _ => {
                "HTTP/1.1 400 Bad Request\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n".to_string()
            }
        }
    }
}