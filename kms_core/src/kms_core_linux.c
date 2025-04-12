#include <openssl/evp.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdbool.h>
#include <sys/epoll.h>

struct PollEvent
{
    int fd;
};

int poller() { return epoll_create1(0); }

int poll_ctl(int epoll_fd, int fd, int ops, int flags)
{
    struct epoll_event evt;
    evt.data.fd = fd;
    evt.events = flags;

    return epoll_ctl(epoll_fd, ops, fd, &evt);
}

// user need to ensure max_event to be within a stack size range
int poll_wait(int epoll_fd, struct PollEvent *output_events, int max_event, int timeout)
{
    struct epoll_event evts[max_event];
    int event_count = epoll_wait(epoll_fd, evts, max_event, timeout);
    for (int i = 0; i < event_count; ++i)
    {
        output_events[i].fd = evts[i].data.fd;
    }

    return event_count;
}

size_t aes_encrypt(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *iv,
    const unsigned char *plain_text, size_t plain_text_len,
    unsigned char *cipher, size_t cipher_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int total_len = 0;

    if (!ctx)
        return 0;

    // Initialize encryption context
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Provide the plaintext to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, cipher, &len, plain_text, plain_text_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, cipher + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

size_t aes_decrypt(
    const unsigned char *secret, size_t secret_len,
    const unsigned char *iv,
    unsigned char *plain_text, size_t plain_text_len,
    const unsigned char *cipher, size_t cipher_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    int total_len = 0;

    if (!ctx)
        return 0;

    // Initialize decryption context
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, secret, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Provide the ciphertext to be decrypted
    if (1 != EVP_DecryptUpdate(ctx, plain_text, &len, cipher, cipher_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plain_text + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

struct RsaKeyPair
{
    void *Pub;
    void *Pri;
};

bool generate_rsa_key_pair(int bit_size, struct RsaKeyPair *key_pair)
{
    bool success = false;
    BIGNUM *e = BN_new();
    RSA *rsa = RSA_new();

    if (!e || !rsa)
        goto cleanup;

    BN_set_word(e, RSA_F4); // Common public exponent 65537

    if (!RSA_generate_key_ex(rsa, bit_size, e, NULL))
        goto cleanup;

    key_pair->Pri = RSAPrivateKey_dup(rsa);
    key_pair->Pub = RSAPublicKey_dup(rsa);

    if (!key_pair->Pri || !key_pair->Pub)
        goto cleanup;

    success = true;

cleanup:
    RSA_free(rsa);
    BN_free(e);
    return success;
}

void destroy_rsa_key(RSA *key)
{
    if (key)
        RSA_free(key);
}

void destroy_rsa_keypair(struct RsaKeyPair key_pair)
{
    destroy_rsa_key(key_pair.Pub);
    destroy_rsa_key(key_pair.Pri);
}

bool rsa_encrypt(
    const unsigned char *plain, size_t plain_len,
    unsigned char *cipher, size_t cipher_len,
    RSA *pub,
    size_t *cipher_out_len)
{
    int result = RSA_public_encrypt(
        (int)plain_len, plain,
        cipher,
        pub,
        RSA_PKCS1_OAEP_PADDING);

    if (result == -1)
    {
        *cipher_out_len = 0;
        return false;
    }

    *cipher_out_len = (size_t)result;
    return true;
}

bool rsa_decrypt(
    unsigned char *plain, size_t plain_len,
    const unsigned char *cipher, size_t cipher_len,
    RSA *pri,
    size_t *plain_out_len)
{
    int result = RSA_private_decrypt(
        (int)cipher_len, cipher,
        plain,
        pri,
        RSA_PKCS1_OAEP_PADDING);

    if (result == -1)
    {
        *plain_out_len = 0;
        return false;
    }

    *plain_out_len = (size_t)result;
    return true;
}
