#ifndef FILEIO_H
#define FILEIO_H

#include <stddef.h>

// Secure file operations with proper error handling
unsigned char *read_file(const char *filename, size_t *file_len);
int write_file(const char *filename, const unsigned char *data, size_t data_len);
int write_encrypted_file(const char *filename, 
                        const unsigned char *iv, 
                        const unsigned char *hmac,
                        const unsigned char *ciphertext, 
                        size_t ciphertext_len);
int read_encrypted_file(const char *filename,
                       unsigned char *iv,
                       unsigned char *hmac,
                       unsigned char **ciphertext,
                       size_t *ciphertext_len);

#endif
