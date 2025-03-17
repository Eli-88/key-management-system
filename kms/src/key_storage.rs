use std::collections::HashMap;
use kms_core::crypto::*;
use crate::interface::{KeyContext, IStorage};

#[derive(Debug, Copy, Clone)]
pub enum CryptoType
{
    AES,
    RSA
}

pub struct KeyStorage {
    aes_map: HashMap<String, [u8; 32]>,
    rsa_map: HashMap<String, RSA>,
    iv : [u8; 16],
}

impl KeyStorage {
    pub(crate) fn new() -> KeyStorage {
        KeyStorage{
            aes_map: Default::default(),
            rsa_map: Default::default(),
            iv : [0; 16]
        }
    }
}

impl IStorage for KeyStorage {
     fn register(&mut self, user_id: &str, key_context: KeyContext) {
        match key_context.crypto_type {
            CryptoType::AES => {
                self.aes_map.insert(user_id.to_string(), AES::generate_secret());
            }
            CryptoType::RSA => {
                let rsa = RSA::new(key_context.rsa_key_size);
                self.rsa_map.insert(user_id.to_string(), rsa);
            }
        }
    }

    fn encrypt(&mut self, user_id: &str, plain: &[u8], cipher: &mut [u8], key_context: KeyContext) -> usize {
        let mut output_len = 0;
        match key_context.crypto_type {
            CryptoType::AES => {
                let secret_key = self.aes_map.get(user_id);
                match secret_key {
                    Some(key) => {
                        output_len = AES::encrypt(key, &self.iv, plain, cipher);
                    }
                    None => {
                        output_len = 0;
                    }
                }
            }
            CryptoType::RSA => {
                let rsa = self.rsa_map.get(user_id);
                match rsa {
                    Some(rsa) => {
                        if rsa.bit_size == key_context.rsa_key_size {
                            if !rsa.encrypt(plain, cipher, &mut output_len) {output_len = 0;}
                        }
                        else {output_len = 0;}
                    }
                    None => {output_len = 0;}
                }
            }
        }

        output_len
    }

    fn decrypt(&mut self, user_id: &str, plain: &mut [u8], cipher: &[u8], key_context: KeyContext) -> usize {
        let mut output_len = 0;

        match key_context.crypto_type {
            CryptoType::AES => {
                let mut secret_key = self.aes_map.get(user_id);
                match secret_key {
                    Some(key) => {
                        output_len = AES::decrypt(key, &self.iv,plain, cipher);
                    }
                    None => {output_len = 0;}
                }
            }
            CryptoType::RSA => {
                let rsa = self.rsa_map.get(user_id);
                match rsa {
                    Some(rsa) => {
                        if rsa.bit_size == key_context.rsa_key_size {
                            if !rsa.decrypt(plain, cipher, &mut output_len) {output_len = 0;}
                        }
                        else {output_len = 0;}
                    }
                    None => {output_len = 0;}
                }
            }
        }

        output_len
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_aes() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::aes());
        assert_eq!(key_storage.aes_map.len(), 1);
        assert!(key_storage.aes_map.contains_key(user_id));
    }

    #[test]
    fn test_register_aes_duplicate() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::aes());
        key_storage.register(&user_id, KeyContext::aes());

        assert_eq!(key_storage.aes_map.len(), 1);
        assert!(key_storage.aes_map.contains_key(user_id));
    }

    #[test]
    fn test_register_rsa() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::rsa(RsaBitSize::Bits2048));

        assert_eq!(key_storage.rsa_map.len(), 1);
        assert!(key_storage.rsa_map.contains_key(user_id));
    }

    #[test]
    fn test_encrypt_aes() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::aes());

        let plain = b"hello world";
        let mut cipher: [u8; 16] = [0; 16];
        let cipher_len = key_storage.encrypt(&user_id, plain, &mut cipher, KeyContext::aes());
        assert_eq!(cipher_len, 16);

        let mut decrypted = [0u8; 100];
        let decrypted_len = key_storage.decrypt(&user_id, &mut decrypted, &cipher, KeyContext::aes());
        assert_eq!(decrypted_len, plain.len());

        assert_eq!(&decrypted[..decrypted_len], plain);
    }

    #[test]
    fn test_encrypt_rsa() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::rsa(RsaBitSize::Bits2048));

        let plain = b"hello world";
        let mut cipher: [u8; 256] = [0; 256];
        let cipher_len = key_storage.encrypt(&user_id, plain, &mut cipher, KeyContext::rsa(RsaBitSize::Bits2048));
        assert_eq!(cipher_len, 256);

        let mut decrypted = [0u8; 100];
        let decrypted_len = key_storage.decrypt(&user_id, &mut decrypted, &cipher, KeyContext::rsa(RsaBitSize::Bits2048));
        assert_eq!(decrypted_len, plain.len());

        assert_eq!(&decrypted[..decrypted_len], plain);
    }

    #[test]
    fn test_encrypt_rsa_wrong_size() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::rsa(RsaBitSize::Bits2048));

        let plain = b"hello world";
        let mut cipher: [u8; 256] = [0; 256];
        let cipher_len = key_storage.encrypt(&user_id, plain, &mut cipher, KeyContext::rsa(RsaBitSize::Bits1024));
        assert_eq!(cipher_len, 0);
    }

    #[test]
    fn test_decrypt_rsa_wrong_size() {
        let mut key_storage = KeyStorage::new();
        let user_id = "test";
        key_storage.register(&user_id, KeyContext::rsa(RsaBitSize::Bits2048));

        let plain = b"hello world";
        let mut cipher: [u8; 256] = [0; 256];
        let cipher_len = key_storage.encrypt(&user_id, plain, &mut cipher, KeyContext::rsa(RsaBitSize::Bits2048));
        assert_eq!(cipher_len, 256);

        let mut decrypted = [0u8; 100];
        let decrypted_len = key_storage.decrypt(&user_id, &mut decrypted, &cipher, KeyContext::rsa(RsaBitSize::Bits1024));
        assert_eq!(decrypted_len, 0);
    }
}