use crate::message::{DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, InvalidRequest, RegisterRequest, RegisterResponse, Request};
use crate::storage_traits::{IStorage, KeyContext};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use httparse::Status;
use kms_core::crypto::RsaBitSize;

fn next_multiple_of_16(size: usize) -> usize { ((size + 16 - 1) / 16) * 16 }

pub fn on_message<T>(storage: &mut T, buffer: &[u8]) -> String where T: IStorage {
    let request = parse(buffer);
    let response = process_message(storage, request);

    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        response.len(),
        response
    );

    response
}

pub fn parse(buffer: &[u8]) -> Request {
    let mut headers = [httparse::Header { name: "", value: &[] }; 32];
    let mut req = httparse::Request::new(&mut headers);
    let mut result: Request = Request::Invalid(InvalidRequest {});

    match req.parse(&buffer) {
        Ok(Status::Complete(sz)) => {
            match req.path {
                Some(path) => {

                    if path.to_lowercase() == "/register" {
                        match serde_json::from_slice::<RegisterRequest>(&buffer[sz..]) {
                            Ok(request) => {
                                result = Request::Register(request);
                            }
                            _=> {
                            }
                        }
                    }

                    if path.to_lowercase() == "/encrypt" {
                        match serde_json::from_slice::<EncryptRequest>(&buffer[sz..]) {
                            Ok(request) => {
                                result = Request::Encrypt(request);
                            }
                            _=> {}
                        }
                    }

                    if path.to_lowercase() == "/decrypt" {
                        match serde_json::from_slice::<DecryptRequest>(&buffer[sz..]) {
                            Ok(request) => {
                                result = Request::Decrypt(request);
                            }
                            _=> {}
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }

    result
}


pub fn process_message<T>(storage: &mut T, request: Request) -> String where T: IStorage {
    let mut response = String::from("Bad Request");
    match request {

        Request::Register(request) => {
            if request.key_type.to_lowercase() == "aes" {
                storage.register(&request.user_id, KeyContext::aes());
                response = serde_json::to_string(&RegisterResponse{result: String::from("OK")}).unwrap();
            }

            if request.key_type.to_lowercase() == "rsa" {
                match request.rsa_key_size {
                    1024 => {
                        storage.register(&request.user_id, KeyContext::rsa(RsaBitSize::Bits1024));
                        response = serde_json::to_string(&RegisterResponse{result: String::from("OK")}).unwrap();
                    }

                    2048 => {
                        storage.register(&request.user_id, KeyContext::rsa(RsaBitSize::Bits2048));
                        response = serde_json::to_string(&RegisterResponse{result: String::from("OK")}).unwrap();
                    }

                    _ => {}
                }
            }
        }


        Request::Encrypt(request) => {
            if request.key_type.to_lowercase() == "aes" {
                let cipher_expected_len = next_multiple_of_16(request.plain_text.len());
                let mut cipher = vec![0u8; cipher_expected_len];
                let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::aes());
                if cipher.len() == cipher_len {
                    response = serde_json::to_string(&EncryptResponse{ cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) }).unwrap();
                }
            }

            if request.key_type.to_lowercase() == "rsa" {
                if request.rsa_key_size == 1024 {
                    let cipher_expected_len = 128;
                    let mut cipher = vec![0u8; cipher_expected_len];
                    let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::rsa(RsaBitSize::Bits1024));
                    if cipher.len() == cipher_len {
                        response = serde_json::to_string(&EncryptResponse{ cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) }).unwrap();
                    }
                }

                if request.rsa_key_size == 2048 {
                    let cipher_expected_len = 256;
                    let mut cipher = vec![0u8; cipher_expected_len];
                    let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::rsa(RsaBitSize::Bits2048));
                    if cipher.len() == cipher_len {
                        response = serde_json::to_string(&EncryptResponse{ cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) }).unwrap();
                    }
                }
            }

        }



        Request::Decrypt(request) => {
            if request.key_type.to_lowercase() == "aes" {
                let cipher = BASE64_STANDARD.decode(&request.cipher_text);
                match cipher {
                    Ok(cipher) => {
                        let plain_len: usize = cipher.len();
                        let mut plain = vec![0u8; plain_len];

                        let plain_output_len = storage.decrypt(&request.user_id, plain.as_mut_slice(), cipher.as_slice(), KeyContext::aes());
                        if plain_len >= plain_output_len {
                            let slice: &[u8] = &plain[..plain_output_len];
                            response = serde_json::to_string(&DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() }).unwrap();
                        }
                    }
                    _ => {}
                }
            }

            if request.key_type.to_lowercase() == "rsa" {
                let cipher = BASE64_STANDARD.decode(&request.cipher_text);
                match cipher {
                    Ok(cipher) => {
                        let plain_len: usize = cipher.len();
                        let mut plain = vec![0u8; plain_len];

                        let mut plain_output_len: usize = 0;
                        if request.rsa_key_size == 1024 {
                            plain_output_len = storage.decrypt(&request.user_id, plain.as_mut_slice(), cipher.as_slice(), KeyContext::rsa(RsaBitSize::Bits1024));
                            if plain_len >= plain_output_len {
                                let slice: &[u8] = &plain[..plain_output_len];
                                response = serde_json::to_string(&DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() }).unwrap();
                            }
                        }

                        if request.rsa_key_size == 2048 {
                            plain_output_len = storage.decrypt(&request.user_id, plain.as_mut_slice(), cipher.as_slice(), KeyContext::rsa(RsaBitSize::Bits2048));
                            if plain_len >= plain_output_len {
                                let slice: &[u8] = &plain[..plain_output_len];
                                response = serde_json::to_string(&DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() }).unwrap();
                            }
                        }
                    }
                    _ => {}
                }

            }
        }

        _ => {}
    }

    response
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_storage::KeyStorage;
    use crate::message::{DecryptRequest, EncryptRequest, RegisterRequest};


    #[test]
    fn test_parse_register() {
        let body = serde_json::to_string(&RegisterRequest{
            user_id : String::from("test user"),
            key_type: String::from("aes"),
            rsa_key_size: 1024
        }).unwrap();

        let path = "/register";

        let message = format!(
            "POST {} HTTP/1.1\r\n\
            Host: localhost\r\n\
            Content-Length: {}\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            {}",
            path,
            body.len(),
            body
        );

        match parse(message.as_bytes()) {
            Request::Register(request) => {
                assert_eq!(request.user_id, String::from("test user"));
                assert_eq!(request.key_type, String::from("aes"));
                assert_eq!(request.rsa_key_size, 1024);
            }
            _ => {assert!(false);}
        }
    }

    #[test]
    fn test_parse_encrypt() {
        let body = serde_json::to_string(&EncryptRequest{
            user_id : String::from("test user"),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            plain_text: String::from("hello world")
        }).unwrap();

        let path = "/encrypt";

        let message = format!(
            "POST {} HTTP/1.1\r\n\
            Host: localhost\r\n\
            Content-Length: {}\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            {}",
            path,
            body.len(),
            body
        );

        match parse(message.as_bytes()) {
            Request::Encrypt(request) => {
                assert_eq!(request.user_id, String::from("test user"));
                assert_eq!(request.key_type, String::from("aes"));
                assert_eq!(request.rsa_key_size, 1024);
                assert_eq!(request.plain_text, String::from("hello world"));
            }
            _ => {assert!(false);}
        }
    }

    #[test]
    fn test_parse_decrypt() {
        let body = serde_json::to_string(&DecryptRequest{
            user_id : String::from("test user"),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            cipher_text: String::from("hello world")
        }).unwrap();

        let path = "/decrypt";

        let message = format!(
            "POST {} HTTP/1.1\r\n\
            Host: localhost\r\n\
            Content-Length: {}\r\n\
            Content-Type: text/plain\r\n\
            \r\n\
            {}",
            path,
            body.len(),
            body
        );

        match parse(message.as_bytes()) {
            Request::Decrypt(request) => {
                assert_eq!(request.user_id, String::from("test user"));
                assert_eq!(request.key_type, String::from("aes"));
                assert_eq!(request.rsa_key_size, 1024);
                assert_eq!(request.cipher_text, String::from("hello world"));
            }
            _ => {assert!(false);}
        }
    }
    #[test]
    fn test_process_register_aes() {
        let mut storage = KeyStorage::new();
        let message = RegisterRequest{
            user_id: String::from("test user"),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
        };

        let response = process_message(&mut storage, Request::Register(message));
    }

    #[test]
    fn test_process_register_rsa() {
        let mut storage = KeyStorage::new();
        let message = RegisterRequest{
            user_id: String::from("test user"),
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
        };

        let response = process_message(&mut storage, Request::Register(message));
    }

    #[test]
    fn test_process_encrypt_aes() {
        let mut storage = KeyStorage::new();
        let user_id = String::from("test user");

        let message = RegisterRequest{
            user_id: String::from(&user_id),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
        };

        process_message(&mut storage, Request::Register(message));

        let plain_text = String::from("hello world");
        let message = EncryptRequest{
            user_id: String::from(&user_id),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            plain_text: plain_text.to_string(),
        };

        let mut cipher_text = String::from("");
        let response = process_message(&mut storage, Request::Encrypt(message));

        match serde_json::from_slice::<EncryptResponse>(response.as_bytes()) {
            Ok(resp) => {
                cipher_text = resp.cipher_text;
            }
            _ => {assert!(false);}
        }

        let message = DecryptRequest {
            user_id,
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            cipher_text,
        };

        let response = process_message(&mut storage, Request::Decrypt(message));
        match serde_json::from_slice::<DecryptResponse>(response.as_bytes()) {
            Ok(resp) => {
                assert_eq!(resp.plain_text, plain_text);
            }
            _ => {assert!(false);}
        }
    }

    #[test]
    fn test_process_encrypt_rsa() {
        let mut storage = KeyStorage::new();
        let user_id = String::from("test user");

        let message = RegisterRequest{
            user_id: String::from(&user_id),
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
        };

        process_message(&mut storage, Request::Register(message));

        let plain_text = String::from("hello world");
        let message = EncryptRequest{
            user_id: String::from(&user_id),
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
            plain_text: plain_text.to_string(),
        };

        let mut cipher_text = String::from("");
        let response = process_message(&mut storage, Request::Encrypt(message));
        match serde_json::from_slice::<EncryptResponse>(response.as_bytes()) {
            Ok(resp) => {
                cipher_text = resp.cipher_text;
            }
            _ => {assert!(false);}
        }

        let message = DecryptRequest {
            user_id,
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
            cipher_text,
        };

        let response = process_message(&mut storage, Request::Decrypt(message));
        match serde_json::from_slice::<DecryptResponse>(response.as_bytes()) {
            Ok(resp) => {
                assert_eq!(resp.plain_text, plain_text);
            }
            _ => assert!(false),
        }
    }
}