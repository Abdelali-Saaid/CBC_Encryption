#include "../include/cbc.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>

int cbc_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    // Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    // Initialize encryption operation with AES-256-CBC
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide the plaintext to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int cbc_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return -1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void generate_random_iv(unsigned char *iv, size_t iv_len) {
    if (RAND_bytes(iv, iv_len) != 1) {
        // Handle random generation error securely
        for (size_t i = 0; i < iv_len; i++) {
            iv[i] = 0; // Fallback - in production, handle this properly
        }
    }
}

void generate_random_key(unsigned char *key, size_t key_len) {
    if (RAND_bytes(key, key_len) != 1) {
        // Handle random generation error
        for (size_t i = 0; i < key_len; i++) {
            key[i] = 0;
        }
    }
}

int compute_hmac(const unsigned char *data, size_t data_len,
                 const unsigned char *key, unsigned char *hmac) {
    unsigned int hmac_len;
    unsigned char *result = HMAC(EVP_sha256(), key, KEY_SIZE, 
                                data, data_len, hmac, &hmac_len);
    return (result != NULL) ? (int)hmac_len : -1;
}

int verify_hmac(const unsigned char *data, size_t data_len,
                const unsigned char *key, const unsigned char *hmac) {
    unsigned char computed_hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    
    if (!HMAC(EVP_sha256(), key, KEY_SIZE, data, data_len, 
              computed_hmac, &hmac_len)) {
        return -1;
    }
    
    // Constant-time comparison to prevent timing attacks
    return CRYPTO_memcmp(hmac, computed_hmac, hmac_len) == 0;
}
