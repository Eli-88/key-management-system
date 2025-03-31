use crate::message::{DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse, RegisterRequest, RegisterResponse};
use crate::interface::{IStorage, KeyContext};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use kms_core::crypto::RsaBitSize;

fn next_multiple_of_16(size: usize) -> usize { ((size + 16 - 1) / 16) * 16 }

pub fn process_register_request<T>(storage: &mut T, buffer: &[u8]) -> Option<String> where T: IStorage {
    let Ok(request) = serde_json::from_slice::<RegisterRequest>(buffer) else {
        return None;
    };

    match request.key_type.to_lowercase().as_str() {
        "aes" => {
            storage.register(&request.user_id, KeyContext::aes());
            Some(serde_json::to_string(&RegisterResponse { result: String::from("OK") }).unwrap())
        }
        "rsa" => {

            let key_size = match request.rsa_key_size{
                1024 => Some(RsaBitSize::Bits1024),
                2048 => Some(RsaBitSize::Bits2048),
                _ => None
            }?;

            storage.register(&request.user_id, KeyContext::rsa(key_size));
            Some(serde_json::to_string(&RegisterResponse { result: String::from("OK") }).unwrap())
        }
        _ => None
    }
}

pub fn process_encrypt_request<T>(storage: &mut T, buffer: &[u8]) -> Option<String> where T: IStorage {
    let Ok(request) = serde_json::from_slice::<EncryptRequest>(buffer) else {
        return None;
    };

    match request.key_type.to_lowercase().as_str() {
        "aes" => {
            let cipher_expected_len = next_multiple_of_16(request.plain_text.len());
            let mut cipher = vec![0u8; cipher_expected_len];
            let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::aes());
            if cipher.len() != cipher_len {
                return None;
            }
            Some(serde_json::to_string(&EncryptResponse { cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) }).unwrap())

        }
        "rsa" => {

            let (key_size, cipher_expected_len) = match request.rsa_key_size {
                1024 => Some((RsaBitSize::Bits1024, 128)),
                2048 => Some((RsaBitSize::Bits2048, 256)),
                _ => None
            }?;

            let mut cipher = vec![0u8; cipher_expected_len];
            let cipher_len = storage.encrypt(&request.user_id, &request.plain_text.as_bytes(), cipher.as_mut_slice(), KeyContext::rsa(key_size));

            if cipher.len() != cipher_len {
                return None;
            }
            
            Some(serde_json::to_string(&EncryptResponse { cipher_text: BASE64_STANDARD.encode(&cipher[..cipher_len]) }).unwrap())
        }
        _ => None
    }
}

pub fn process_decrypt_request<T>(storage: &mut T, buffer: &[u8]) -> Option<String> where T: IStorage {
    let Ok(request) = serde_json::from_slice::<DecryptRequest>(buffer) else {
        return None;
    };

    let cipher = BASE64_STANDARD.decode(&request.cipher_text);
    let Ok(cipher) = cipher else {
        return None;
    };

    match request.key_type.to_lowercase().as_str() {
        "aes" => {
            let plain_len: usize = cipher.len();
            let mut plain = vec![0u8; plain_len];

            let plain_output_len = storage.decrypt(&request.user_id, plain.as_mut_slice(), cipher.as_slice(), KeyContext::aes());
            if plain_len < plain_output_len {
                return None;
            }

            let slice: &[u8] = &plain[..plain_output_len];
            Some(serde_json::to_string(&DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() }).unwrap())
        },
        "rsa" => {
            let plain_len: usize = cipher.len();
            let mut plain = vec![0u8; plain_len];

            let mut plain_output_len: usize = 0;

            let key_size = match request.rsa_key_size {
                1024 => Some(RsaBitSize::Bits1024),
                2048 => Some(RsaBitSize::Bits2048),
                _ => None
            }?;

            plain_output_len = storage.decrypt(&request.user_id, plain.as_mut_slice(), cipher.as_slice(), KeyContext::rsa(key_size));
            if plain_output_len < plain_output_len {
                return None;
            }

            let slice: &[u8] = &plain[..plain_output_len];
            Some(serde_json::to_string(&DecryptResponse { plain_text: String::from_utf8_lossy(slice).to_string() }).unwrap())
        },
        _ => None
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

        let request = serde_json::to_string(&message).unwrap();
        match process_register_request(&mut storage, request.as_bytes()) {
            Some(message) => {
                match serde_json::from_slice::<RegisterResponse>(message.as_bytes()) {
                    Ok(message) => {

                    }
                    _ => assert!(false),
                }
            }
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

        let request = serde_json::to_string(&message).unwrap();
        match process_register_request(&mut storage, request.as_bytes()) {
            Some(message) => {
                match serde_json::from_slice::<RegisterResponse>(message.as_bytes()) {
                    Ok(message) => {

                    }
                    _ => assert!(false),
                }
            }
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

        let request = serde_json::to_string(&message).unwrap();

        process_register_request(&mut storage, request.as_bytes());

        let plain_text = String::from("hello world");
        let message = EncryptRequest{
            user_id: String::from(&user_id),
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            plain_text: plain_text.to_string(),
        };

        let mut cipher_text = String::from("");

        let request = serde_json::to_string(&message).unwrap();
        match process_encrypt_request(&mut storage, request.as_bytes()) {
            Some(message) => {
                match serde_json::from_slice::<EncryptResponse>(message.as_bytes()) {
                    Ok(message) => {
                         cipher_text = message.cipher_text;
                    }
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        }

        let message = DecryptRequest {
            user_id,
            key_type: String::from("aes"),
            rsa_key_size: 1024,
            cipher_text,
        };

        let request = serde_json::to_string(&message).unwrap();
        match process_decrypt_request(&mut storage, request.as_bytes()) {
            Some(message) => {
                match serde_json::from_slice::<DecryptResponse>(message.as_bytes()) {
                    Ok(message) => {
                        assert_eq!(message.plain_text, plain_text);
                    }
                    _ => assert!(false),
                }
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

        let request = serde_json::to_string(&message).unwrap();

        process_register_request(&mut storage, request.as_bytes());

        let plain_text = String::from("hello world");
        let message = EncryptRequest{
            user_id: String::from(&user_id),
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
            plain_text: plain_text.to_string(),
        };

        let mut cipher_text = String::from("");

        let request = serde_json::to_string(&message).unwrap();
        match process_encrypt_request(&mut storage, request.as_bytes()) {
            Some(message) => {
                match serde_json::from_slice::<EncryptResponse>(message.as_bytes()) {
                    Ok(message) => {
                        cipher_text = message.cipher_text;
                    }
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        }

        let message = DecryptRequest {
            user_id,
            key_type: String::from("rsa"),
            rsa_key_size: 1024,
            cipher_text,
        };

        let request = serde_json::to_string(&message).unwrap();
        match process_decrypt_request(&mut storage, request.as_bytes()) {
            Some(message) => {
                match serde_json::from_slice::<DecryptResponse>(message.as_bytes()) {
                    Ok(message) => {
                        assert_eq!(message.plain_text, plain_text);
                    }
                    _ => assert!(false),
                }
            }
            _ => assert!(false),
        }
    }
}