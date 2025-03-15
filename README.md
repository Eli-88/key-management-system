# Rust Key Management System (KMS)

This project demonstrates a **Key Management System (KMS)** built in **Rust** that wraps C system calls and macOS native cryptographic APIs. It provides an executable service for encryption and decryption. This project can also serve as an exercise for learning Rust and working with native APIs.

## Purpose

The primary goal of this project is to provide an executable **Key Management System (KMS)** that wraps macOS's native cryptographic API for encryption and decryption services. Additionally, this project demonstrates how to wrap system calls in Rust for interacting with C APIs, providing a hands-on learning exercise.

## Usage

This document demonstrates how to interact with the Key Management System API using `curl` commands for registering a user, encrypting data, and decrypting data.

### 1. Register User

- register a user with the desired key type and RSA key size. The kms will generate the key pair and stored in memory

```bash
curl -X POST http://localhost:8080/register \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": "user123",
        "key_type": "RSA",
        "rsa_key_size": 2048
    }'
```

### 2. Encrypt the plain text
```bash
curl -X POST http://localhost:8080/encrypt \
-H "Content-Type: application/json" \
-d '{
"user_id": "user123",
"key_type": "RSA",
"rsa_key_size": 2048,
"plain_text": "This is a secret message."
}'
```

- Sample encrypted result
```
{
    "cipher_text": "ENCRYPTED_TEXT"
}
```

### 3. Decrypt cipher text 
- Replace the cipher text below with the actual cipher
```bash
curl -X POST http://localhost:8080/decrypt \
    -H "Content-Type: application/json" \
    -d '{
        "user_id": "user123",
        "key_type": "RSA",
        "rsa_key_size": 2048,
        "cipher_text": "ENCRYPTED_TEXT"
    }'
 
```
- Sample decrypted result
```
{
    "plain_text": "This is a secret message."
}
```

