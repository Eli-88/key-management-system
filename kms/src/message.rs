use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct RegisterRequest {
    pub user_id: String,
    pub key_type: String,
    pub rsa_key_size: usize,
}

#[derive(Deserialize, Debug)]
pub struct EncryptRequest {
    pub user_id: String,
    pub key_type: String,
    pub rsa_key_size: usize,
    pub plain_text: String,
}

#[derive(Deserialize, Debug)]
pub struct DecryptRequest {
    pub user_id: String,
    pub key_type: String,
    pub rsa_key_size: usize,
    pub cipher_text: String,
}

#[derive(Deserialize, Debug)]
pub struct InvalidRequest {}

#[derive(Serialize, Debug)]
pub struct RegisterResponse {
    pub result: String,
}

#[derive(Serialize, Debug)]
pub struct EncryptResponse {
    pub cipher_text: String,
}

#[derive(Serialize, Debug)]
pub struct DecryptResponse {
    pub plain_text: String,
}

#[derive(Serialize, Debug)]
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

pub enum Response
{
    Register(RegisterResponse),
    Encrypt(EncryptResponse),
    Decrypt(DecryptResponse),
    Invalid(InvalidResponse),
}