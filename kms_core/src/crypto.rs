use std::ffi::c_void;
use std::io::Read;
use std::ptr::null_mut;
use rand::{Rng, RngCore};

pub const CC_SHA256_DIGEST_LENGTH: usize = 32;          /* digest length in bytes */
pub const CC_SHA256_BLOCK_BYTES: usize   = 64;          /* block size in bytes */
pub const CC_SHA224_DIGEST_LENGTH: usize = 28;          /* digest length in bytes */
pub const CC_SHA224_BLOCK_BYTES: usize   = 64;          /* block size in bytes */
pub const CC_SHA1_DIGEST_LENGTH: usize   = 20;          /* digest length in bytes */
pub const CC_SHA1_BLOCK_BYTES: usize     = 64;          /* block size in bytes */

pub const K_CCKEY_SIZE_AES128: usize = 16;
pub const K_CCKEY_SIZE_AES192: usize = 24;
pub const K_CCKEY_SIZE_AES256: usize = 32;

pub struct AES;
impl AES {
    pub fn generate_secret() -> [u8; 32] {
        let mut random = rand::rng();
        let mut key: [u8;32] = [0;32];
        random.fill(&mut key);

        key
    }

    pub fn encrypt(secret: &[u8], iv: &[u8; 16], plain_text: &[u8], cipher: &mut [u8]) -> usize {
        let secret_len = secret.len();
        let plain_text_len = plain_text.len();
        let cipher_len = cipher.len();

        unsafe {
            aes_encrypt(
                secret.as_ptr(), secret_len,
                iv.as_ptr(),
                plain_text.as_ptr(), plain_text_len,
                cipher.as_mut_ptr(), cipher_len)
        }
    }

    pub fn decrypt(secret: &[u8], iv: &[u8; 16], plain_text: &mut [u8], cipher: &[u8]) -> usize {
        let secret_len = secret.len();
        let plain_text_len = plain_text.len();
        let cipher_len = cipher.len();

        unsafe {
            aes_decrypt(
                secret.as_ptr(), secret_len,
                iv.as_ptr(),
                plain_text.as_mut_ptr(), plain_text_len,
                cipher.as_ptr(), cipher_len
            )
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RsaKeyPair {
    pub pub_key: *mut c_void,
    pub pri_key: *mut c_void,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RsaBitSize
{
    Bits1024 = 1024,
    Bits2048 = 2048,
    Bits4096 = 4096,
}

pub struct RSA
{
    key_pair: RsaKeyPair,
    pub bit_size: RsaBitSize,
}


impl Drop for RSA {
    fn drop(&mut self) {
        unsafe { destroy_rsa_keypair(self.key_pair) }
    }
}

impl RSA {
    pub fn new(bit_size: RsaBitSize) -> RSA {
        unsafe {
            let mut key_pair = RsaKeyPair{ pub_key: null_mut(), pri_key: null_mut() };
            generate_rsa_key_pair(bit_size as i32, &mut key_pair);

            RSA { key_pair, bit_size }
        }
    }

    pub fn encrypt(
        &self,
        plain: &[u8],
        cipher: &mut [u8],
        cipher_out_len: &mut usize) -> bool {
        unsafe {
            let plain_len = plain.len();
            let cipher_len = cipher.len();

            rsa_encrypt(
                plain.as_ptr(), plain_len,
                cipher.as_mut_ptr(), cipher_len,
                self.key_pair.pub_key,
                cipher_out_len
            )
        }
    }

    pub fn decrypt(
        &self,
        plain: &mut [u8],
        cipher: &[u8],
        plain_out_len: &mut usize) -> bool {
        unsafe {
            let plain_len = plain.len();
            let cipher_len = cipher.len();
            rsa_decrypt(
                plain.as_mut_ptr(), plain_len,
                cipher.as_ptr(), cipher_len,
                self.key_pair.pri_key,
                plain_out_len
            )
        }
    }
}

unsafe extern "C" {
    pub fn sha_256(data: *const u8, len: i32, output_hash: *mut u8);

    pub fn aes_decrypt(
        secret: *const u8, secret_len: usize,
        iv: *const u8,
        plain_text: *mut u8, plain_text_len: usize,
        cipher: *const u8, cipher_len: usize) -> usize;

    pub fn aes_encrypt(
        secret: *const u8, secret_len: usize,
        iv: *const u8,
        plain_text: *const u8, plain_text_len: usize,
        cipher: *mut u8, cipher_len: usize) -> usize;

    pub fn generate_rsa_key_pair(bit_size: i32, key_pair: *mut RsaKeyPair) -> bool;
    pub fn destroy_rsa_key(key: *const c_void);
    pub fn destroy_rsa_keypair(key_pair: RsaKeyPair);

    pub fn rsa_encrypt(
        plain: *const u8, plain_len: usize,
        cipher: *mut u8, cipher_len: usize,
        pub_key: *const c_void,
        cipher_out_len: &mut usize) -> bool;

    pub fn rsa_decrypt(
        plain: *mut u8, plain_len: usize,
        cipher: *const u8, cipher_len: usize,
        pri: *const c_void,
        plain_out_len: &mut usize) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt() {
        let secret = AES::generate_secret();
        let iv: [u8; 16] = [0u8; 16];

        let plain = "plain text";
        let mut cipher: [u8; 16] = [0u8; 16];

        let cipher_len = AES::encrypt(&secret, &iv, &plain.as_bytes(), &mut cipher);
        assert_eq!(cipher_len, 16);

        let mut decoded_plain: [u8; 16] = [0u8; 16];
        let decoded_plain_len = AES::decrypt(&secret, &iv, &mut decoded_plain, &cipher);

        assert_eq!(decoded_plain_len, plain.len());
        assert_eq!(&decoded_plain[0..decoded_plain_len], plain.as_bytes());
    }

    #[test]
    fn test_aes_cipher_too_small() {
        let secret = AES::generate_secret();
        let iv: [u8; 16] = [0u8; 16];

        let plain = "plain text";
        const TRUNCATE_CIPHER_LEN: usize = 10;
        let mut truncate_cipher: [u8; TRUNCATE_CIPHER_LEN] = [0u8; TRUNCATE_CIPHER_LEN];

        let truncate_cipher_out_len = AES::encrypt(&secret, &iv, &plain.as_bytes(), &mut truncate_cipher);
        assert_eq!(truncate_cipher_out_len, 16);

        let mut cipher: [u8; 16] = [0u8; 16];
        let cipher_out_len = AES::encrypt(&secret, &iv, &plain.as_bytes(), &mut cipher);
        assert_eq!(cipher_out_len, 16);
    }

    #[test]
    fn test_aes_cipher_more_than_enough() {
        let secret: [u8; K_CCKEY_SIZE_AES256] = [1u8; K_CCKEY_SIZE_AES256];
        let iv: [u8; 16] = [0u8; 16];

        let plain = "plain text";
        const BIG_CIPHER_LEN: usize = 100;
        let mut big_cipher: [u8; BIG_CIPHER_LEN] = [0u8; BIG_CIPHER_LEN];

        let big_cipher_out_len = AES::encrypt(&secret, &iv, &plain.as_bytes(), &mut big_cipher);
        assert_eq!(big_cipher_out_len, 16);

        let mut cipher: [u8; 16] = [0u8; 16];
        let cipher_len = AES::encrypt(&secret, &iv, &plain.as_bytes(), &mut cipher);
        assert_eq!(cipher_len, 16);

        assert_eq!(big_cipher[..cipher.len()], cipher);
    }

    #[test]
    fn test_rsa_encrypt_1024() {
        let rsa = RSA::new(RsaBitSize::Bits1024);

        let plain = "hello rsa";
        let mut cipher: [u8; 128] = [0u8; 128];
        let mut cipher_len: usize = 0;

        assert!(rsa.encrypt(plain.as_bytes(), &mut cipher, &mut cipher_len));
        assert_eq!(cipher_len, 128);

        let mut decoded_plain: [u8; 12] = [0u8; 12];
        let mut decoded_plain_len: usize = 0;
        assert!(rsa.decrypt(decoded_plain.as_mut(), &mut cipher, &mut decoded_plain_len));
        assert_eq!(decoded_plain_len, plain.len());

        assert_eq!(&decoded_plain[0..decoded_plain_len], plain.as_bytes());
    }

    #[test]
    fn test_rsa_encrypt_2048() {
        let rsa = RSA::new(RsaBitSize::Bits2048);

        let plain = "hello rsa";
        let mut cipher: [u8; 256] = [0u8; 256];
        let mut cipher_len: usize = 0;

        assert!(rsa.encrypt(plain.as_bytes(), &mut cipher, &mut cipher_len));
        assert_eq!(cipher_len, 256);

        let mut decoded_plain: [u8; 12] = [0u8; 12];
        let mut decoded_plain_len: usize = 0;
        assert!(rsa.decrypt(decoded_plain.as_mut(), &mut cipher, &mut decoded_plain_len));
        assert_eq!(decoded_plain_len, plain.len());

        assert_eq!(&decoded_plain[0..decoded_plain_len], plain.as_bytes());
    }

    #[ignore] // takes too much time, skip this test for now
    #[test]
    fn test_rsa_encrypt_4096() {
        let rsa = RSA::new(RsaBitSize::Bits4096);

        let plain = "hello rsa";
        let mut cipher: [u8; 512] = [0u8; 512];
        let mut cipher_len: usize = 0;

        assert!(rsa.encrypt(plain.as_bytes(), &mut cipher, &mut cipher_len));
        assert_eq!(cipher_len, 512);

        let mut decoded_plain: [u8; 12] = [0u8; 12];
        let mut decoded_plain_len: usize = 0;
        assert!(rsa.decrypt(decoded_plain.as_mut(), &mut cipher, &mut decoded_plain_len));
        assert_eq!(decoded_plain_len, plain.len());

        assert_eq!(&decoded_plain[0..decoded_plain_len], plain.as_bytes());
    }
}