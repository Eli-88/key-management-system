use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug)]
pub struct RegisterRequest {
    pub user_id: String,
    pub key_type: String,
    pub rsa_key_size: usize,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct EncryptRequest {
    pub user_id: String,
    pub key_type: String,
    pub rsa_key_size: usize,
    pub plain_text: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DecryptRequest {
    pub user_id: String,
    pub key_type: String,
    pub rsa_key_size: usize,
    pub cipher_text: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct InvalidRequest {}

#[derive(Serialize, Deserialize, Debug)]
pub struct RegisterResponse {
    pub result: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptResponse {
    pub cipher_text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptResponse {
    pub plain_text: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InvalidResponse {
    pub result: String,
}

pub enum Request
{
    Register(RegisterRequest),
    Encrypt(EncryptRequest),
    Decrypt(DecryptRequest),
    Invalid(InvalidRequest),
}