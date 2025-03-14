use crate::message::{DecryptResponse, EncryptResponse, InvalidResponse, RegisterResponse, Request, Response};
use crate::storage_traits::{IStorage, KeyContext};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use kms_core::crypto::RsaBitSize;


fn next_multiple_of_16(size: usize) -> usize { ((size + 16 - 1) / 16) * 16 }

pub struct Handler;
impl Handler {
    pub fn process_message<T>(storage: &mut T, request: Request) -> Response where T: IStorage {

        let mut response = Response::Invalid(InvalidResponse { result: String::from("ERROR")});

        match request {

            Request::Register(request) => {
                if request.key_type.to_lowercase() == "aes" {
                    storage.register(&request.user_id, KeyContext::aes());
                    response = Response::Register(RegisterResponse{ result: String::from("OK")});
                }

                if request.key_type.to_lowercase() == "rsa" {
                    match request.rsa_key_size {
                        1024 => {
                            storage.register(&request.user_id, KeyContext::rsa(RsaBitSize::Bits1024));
                            response = Response::Register(RegisterResponse{ result: String::from("OK")});
                        }

                        2048 => {
                            storage.register(&request.user_id, KeyContext::rsa(RsaBitSize::Bits2048));
                            response = Response::Register(RegisterResponse{ result: String::from("OK")});
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
                        response = Response::Encrypt(EncryptResponse{ cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) });
                    }
                }

                if request.key_type.to_lowercase() == "rsa" {
                    if request.rsa_key_size == 1024 {
                        let cipher_expected_len = 128;
                        let mut cipher = vec![0u8; cipher_expected_len];
                        let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::rsa(RsaBitSize::Bits1024));
                        if cipher.len() == cipher_len {
                            response = Response::Encrypt(EncryptResponse{ cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) });
                        }
                    }

                    if request.rsa_key_size == 2048 {
                        let cipher_expected_len = 256;
                        let mut cipher = vec![0u8; cipher_expected_len];
                        let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::rsa(RsaBitSize::Bits2048));
                        if cipher.len() == cipher_len {
                            response = Response::Encrypt(EncryptResponse{ cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) });
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
                                response = Response::Decrypt(DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() });
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
                                    response = Response::Decrypt(DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() });
                                }
                            }

                            if request.rsa_key_size == 2048 {
                                plain_output_len = storage.decrypt(&request.user_id, plain.as_mut_slice(), cipher.as_slice(), KeyContext::rsa(RsaBitSize::Bits2048));
                                if plain_len >= plain_output_len {
                                    let slice: &[u8] = &plain[..plain_output_len];
                                    response = Response::Decrypt(DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() });
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_storage::KeyStorage;
    use crate::message::{DecryptRequest, EncryptRequest, RegisterRequest};

    #[test]
    fn test_process_register_aes() {
        let mut storage = KeyStorage::new();
        let message = RegisterRequest{
            user_id: String::from("test user"),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
        };

        let response = Handler::process_message(&mut storage, Request::Register(message));
        match response {
            Response::Register(response) => {}
            _ => assert!(false),
        }
    }

    #[test]
    fn test_process_register_rsa() {
        let mut storage = KeyStorage::new();
        let message = RegisterRequest{
            user_id: String::from("test user"),
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
        };

        let response = Handler::process_message(&mut storage, Request::Register(message));
        match response {
            Response::Register(response) => {}
            _ => assert!(false),
        }
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

        Handler::process_message(&mut storage, Request::Register(message));

        let plain_text = String::from("hello world");
        let message = EncryptRequest{
            user_id: String::from(&user_id),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            plain_text: plain_text.to_string(),
        };

        let mut cipher_text = String::from("");
        let response = Handler::process_message(&mut storage, Request::Encrypt(message));
        match response {
            Response::Encrypt(response) => {
                cipher_text = response.cipher_text;
            }
            _ => assert!(false),
        }

        let message = DecryptRequest {
            user_id,
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            cipher_text,
        };

        let response = Handler::process_message(&mut storage, Request::Decrypt(message));
        match response {
            Response::Decrypt(response) => {
                assert_eq!(response.plain_text, plain_text);
            }
            _ => assert!(false),
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

        Handler::process_message(&mut storage, Request::Register(message));

        let plain_text = String::from("hello world");
        let message = EncryptRequest{
            user_id: String::from(&user_id),
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
            plain_text: plain_text.to_string(),
        };

        let mut cipher_text = String::from("");
        let response = Handler::process_message(&mut storage, Request::Encrypt(message));
        match response {
            Response::Encrypt(response) => {
                cipher_text = response.cipher_text;
            }
            _ => assert!(false),
        }

        let message = DecryptRequest {
            user_id,
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
            cipher_text,
        };

        let response = Handler::process_message(&mut storage, Request::Decrypt(message));
        match response {
            Response::Decrypt(response) => {
                assert_eq!(response.plain_text, plain_text);
            }
            _ => assert!(false),
        }
    }
}