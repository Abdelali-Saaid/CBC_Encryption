#ifndef CBC_H
#define CBC_H

#include <stddef.h>
#include <stdint.h>

#define BLOCK_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16

int cbc_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *ciphertext);

int cbc_decrypt(const unsigned char *ciphertext, size_t ciphertext_len,
                const unsigned char *key, const unsigned char *iv,
                unsigned char *plaintext);

void generate_random_iv(unsigned char *iv, size_t iv_len);
void generate_random_key(unsigned char *key, size_t key_len);

// Authentication
int compute_hmac(const unsigned char *data, size_t data_len,
                 const unsigned char *key, unsigned char *hmac);
int verify_hmac(const unsigned char *data, size_t data_len,
                const unsigned char *key, const unsigned char *hmac);

#endif
