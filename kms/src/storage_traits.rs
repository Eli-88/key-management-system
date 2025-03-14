use kms_core::crypto::RsaBitSize;
use crate::key_storage::CryptoType;

#[derive(Debug, Copy, Clone)]
pub struct KeyContext
{
    pub crypto_type: CryptoType,
    pub rsa_key_size: RsaBitSize, // ignore if crypto type is AES
}

impl KeyContext {
    pub fn aes() -> KeyContext {KeyContext{crypto_type : CryptoType::AES, rsa_key_size: RsaBitSize::Bits2048 }}
    pub fn rsa(bit_size : RsaBitSize) -> KeyContext { KeyContext{crypto_type : CryptoType::RSA, rsa_key_size: bit_size } }
}

pub trait IStorage
{
    fn register(&mut self, user_id: &str, key_context: KeyContext);
    fn encrypt(&mut self, user_id: &str, plain: &[u8], cipher: &mut [u8], key_context: KeyContext) -> usize;
    fn decrypt(&mut self, user_id: &str, plain: &mut [u8], cipher: &[u8], key_context: KeyContext) -> usize;
}