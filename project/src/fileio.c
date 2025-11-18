#include "../include/fileio.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *read_file(const char *filename, size_t *file_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size <= 0) {
        fclose(file);
        return NULL;
    }

    unsigned char *buffer = malloc(size);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    if (fread(buffer, 1, size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        return NULL;
    }

    fclose(file);
    *file_len = size;
    return buffer;
}

int write_file(const char *filename, const unsigned char *data, size_t data_len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        return -1;
    }

    if (fwrite(data, 1, data_len, file) != data_len) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

int write_encrypted_file(const char *filename, 
                        const unsigned char *iv, 
                        const unsigned char *hmac,
                        const unsigned char *ciphertext, 
                        size_t ciphertext_len) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        return -1;
    }

    // Write IV (16 bytes)
    if (fwrite(iv, 1, IV_SIZE, file) != IV_SIZE) {
        fclose(file);
        return -1;
    }

    // Write HMAC (32 bytes for SHA256)
    if (fwrite(hmac, 1, 32, file) != 32) {
        fclose(file);
        return -1;
    }

    // Write ciphertext
    if (fwrite(ciphertext, 1, ciphertext_len, file) != ciphertext_len) {
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}

int read_encrypted_file(const char *filename,
                       unsigned char *iv,
                       unsigned char *hmac,
                       unsigned char **ciphertext,
                       size_t *ciphertext_len) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    // Read IV
    if (fread(iv, 1, IV_SIZE, file) != IV_SIZE) {
        fclose(file);
        return -1;
    }

    // Read HMAC
    if (fread(hmac, 1, 32, file) != 32) {
        fclose(file);
        return -1;
    }

    // Get file size to determine ciphertext length
    fseek(file, 0, SEEK_END);
    long total_size = ftell(file);
    fseek(file, IV_SIZE + 32, SEEK_SET); // Position after IV and HMAC
    
    *ciphertext_len = total_size - (IV_SIZE + 32);
    *ciphertext = malloc(*ciphertext_len);
    if (!*ciphertext) {
        fclose(file);
        return -1;
    }

    if (fread(*ciphertext, 1, *ciphertext_len, file) != *ciphertext_len) {
        free(*ciphertext);
        fclose(file);
        return -1;
    }

    fclose(file);
    return 0;
}
