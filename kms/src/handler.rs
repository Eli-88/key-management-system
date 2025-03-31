use crate::interface::{IHandler, IStorage};
use httparse::Status;
use std::collections::HashMap;

pub struct HttpHandler<T> where T: IStorage
{
    router: HashMap<String, fn(&mut T, &[u8]) -> Option<String>>,
}

impl<T> HttpHandler<T> where T: IStorage {
    pub fn new() -> Self {
        HttpHandler { router: HashMap::new() }
    }

    pub fn register(&mut self, path: &str, callback: fn(&mut T, &[u8]) -> Option<String>) {
        self.router.insert(path.to_string(), callback);
    }
}

impl<T> IHandler<T> for HttpHandler<T> where T: IStorage {
    fn on_message(&self, storage: &mut T, buffer: &[u8]) -> String {
        let mut headers = [httparse::Header { name: "", value: &[] }; 32];
        let mut req = httparse::Request::new(&mut headers);

        let bad_response =
            "HTTP/1.1 400 Bad Request\r\n\
            Content-Length: 0\r\n\
            Connection: close\r\n\r\n";

        let Ok(Status::Complete(sz)) = req.parse(buffer) else {
            return bad_response.to_string();
        };

        let Some(path) = req.path else {
            return bad_response.to_string();
        };

        let Some(ops) = self.router.get(path) else {
            return bad_response.to_string();
        };

        let response = ops(storage, &buffer[sz..]);

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
            _ => bad_response.to_string()
        }
    }
}