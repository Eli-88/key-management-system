use std::collections::HashMap;
use httparse::Status;
use crate::api;
use crate::interface::{IHandler, IStorage};

pub struct HttpHandler<T> where T: IStorage
{
    router: HashMap<String, fn(&mut T, &[u8]) -> Option<String>>,
}

impl<T> HttpHandler<T> where T: IStorage {
    pub fn new() -> Self {
        let mut router: HashMap<String, fn(&mut T, &[u8]) -> Option<String>> = HashMap::new();
        router.insert(String::from("/register"), api::process_register_request);
        router.insert(String::from("/encrypt"), api::process_encrypt_request);
        router.insert(String::from("/decrypt"), api::process_decrypt_request);

        HttpHandler { router }
    }
}

impl<T> IHandler<T> for HttpHandler<T> where T: IStorage {
    fn on_message(&self, storage: &mut T, buffer: &[u8]) -> String {
        let mut headers = [httparse::Header { name: "", value: &[] }; 32];
        let mut req = httparse::Request::new(&mut headers);

        let mut response: Option<String> = None;
        if let Ok(Status::Complete(sz)) = req.parse(&buffer) {
            if let Some(path) = req.path {
                if let Some(ops) = self.router.get(path) {
                    response = ops(storage, &buffer[sz..]);
                }
            }
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