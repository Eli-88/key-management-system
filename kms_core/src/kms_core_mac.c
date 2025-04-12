#include <sys/event.h>
#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>


#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct PollEvent
{
    int fd;
};

int poller() {return kqueue();}
int poll_ctl(int kq, int fd, int filter, int flags)
{
    struct kevent evt;
    EV_SET(&evt, fd, filter, flags, 0, 0, NULL);

    return kevent(kq, &evt, 1, NULL, 0, NULL);
}

// user need to ensure max_event to be within a stack size range
int poll_wait(int kq, struct PollEvent* output_events, int max_event, int timeout)
{
    struct kevent evts[max_event];

    struct timespec spec;
    spec.tv_nsec = 0;
    spec.tv_sec = timeout;

    int event_count = kevent(kq, NULL, 0, evts, max_event, timeout > 0 ? &spec : NULL);
    for(int i = 0; i < event_count; ++i) {output_events[i].fd = evts[i].ident;}

    return event_count;
}


void sha_256(const unsigned char* data, int len, unsigned char* output_hash) {CC_SHA256(data, len, output_hash);}
void sha_224(const unsigned char* data, int len, unsigned char* output_hash) {CC_SHA224(data, len, output_hash);}
void sha_1(const unsigned char* data, int len, unsigned char* output_hash) {CC_SHA1(data, len, output_hash);}

size_t aes_encrypt(
    const unsigned char* secret, size_t secret_len,
    const unsigned char* iv,
    const unsigned char* plain_text, size_t plain_text_len,
    unsigned char* cipher, size_t cipher_len)
{
    size_t output_len = -1;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, secret, secret_len, iv, plain_text, plain_text_len, cipher, cipher_len, &output_len);
    return output_len;
}

size_t aes_decrypt(
    const unsigned char* secret, size_t secret_len,
    const unsigned char* iv,
    unsigned char* plain_text, size_t plain_text_len,
    const unsigned char* cipher, size_t cipher_len)
{
    size_t output_len = -1;
    CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, secret, secret_len, iv, cipher, cipher_len, plain_text, plain_text_len, &output_len);
    return output_len;
}


struct RsaKeyPair
{
    void* Pub;
    void* Pri;
};

bool generate_rsa_key_pair(int bit_size, struct RsaKeyPair* key_pair)
{
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(
        NULL,
        0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);

    CFNumberRef key_size = CFNumberCreate(NULL, kCFNumberIntType, &bit_size);
    CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, key_size);
    CFRelease(key_size);
    SecKeyRef pub_key = NULL;
    SecKeyRef pri_key = NULL;
    OSStatus status = SecKeyGeneratePair(attributes, &pub_key, &pri_key);

    CFRelease(attributes);

    if(status != errSecSuccess)
    {
        key_pair->Pub = NULL;
        key_pair->Pri = NULL;
        return false;
    }

    key_pair->Pub = pub_key;
    key_pair->Pri = pri_key;
    return true;
}

void destroy_rsa_key(void* key) { if(key != NULL) {CFRelease(key);}}
void destroy_rsa_keypair(struct RsaKeyPair key_pair)
{
    destroy_rsa_key(key_pair.Pub);
    destroy_rsa_key(key_pair.Pri);
}

bool rsa_encrypt(
    const unsigned char* plain, size_t plain_len,
    unsigned char* cipher, size_t cipher_len,
    void* pub,
    size_t* cipher_out_len)
{
    bool success = false;
    CFErrorRef error = NULL;

    CFDataRef plain_ref = CFDataCreate(NULL, plain, plain_len);
    CFDataRef cipher_ref = SecKeyCreateEncryptedData(
        pub,
        kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
        plain_ref,
        &error);

    do {
        if(error) { break; }

        size_t output_len = CFDataGetLength(cipher_ref);
        unsigned char* output = CFDataGetBytePtr(cipher_ref);

        memcpy(cipher, output, MIN(cipher_len, output_len));
        *cipher_out_len = output_len;

        success = true;
    } while(0);

    if(plain_ref)  {CFRelease(plain_ref);}
    if(cipher_ref) {CFRelease(cipher_ref);}
    return success;
}

bool rsa_decrypt(
    unsigned char* plain, size_t plain_len,
    const unsigned char* cipher, size_t cipher_len,
    void* pri,
    size_t* plain_out_len)
{
    bool success = false;

    CFErrorRef error = NULL;
    CFDataRef cipher_ref = CFDataCreate(NULL, cipher, cipher_len);

    CFDataRef plain_ref = SecKeyCreateDecryptedData(
        pri,
        kSecKeyAlgorithmRSAEncryptionOAEPSHA1,
        cipher_ref,
        &error
    );

    do {
        if(error) {break;}

        unsigned char* output = CFDataGetBytePtr(plain_ref);
        size_t output_len = CFDataGetLength(plain_ref);
        memcpy(plain, output, MIN(output_len, plain_len));

        *plain_out_len = output_len;
        success = true;

    } while(0);

    if(plain_ref)  {CFRelease(plain_ref);}
    if(cipher_ref) {CFRelease(cipher_ref);}
    return success;
}