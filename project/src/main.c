#include "../include/cbc.h"
#include "../include/fileio.h"
#include "../include/linkedlist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char hmac[32];
    
    // Generate random key and IV
    generate_random_key(key, KEY_SIZE);
    generate_random_iv(iv, IV_SIZE);

    // Read file as binary data
    size_t file_len;
    unsigned char *file_data = read_file("project/Makefiles/input.txt", &file_len);
    if (!file_data) {
        printf("Error reading file\n");
        return 1;
    }

    printf("Original data length: %zu bytes\n", file_len);

    // Encrypt the data
    unsigned char *ciphertext = malloc(file_len + BLOCK_SIZE); // Padding space
    int ciphertext_len = cbc_encrypt(file_data, file_len, key, iv, ciphertext);
    
    if (ciphertext_len < 0) {
        printf("Encryption failed\n");
        free(file_data);
        return 1;
    }

    // Compute HMAC for authentication
    if (compute_hmac(ciphertext, ciphertext_len, key, hmac) < 0) {
        printf("HMAC computation failed\n");
        free(file_data);
        free(ciphertext);
        return 1;
    }

    // Write encrypted file with IV and HMAC
    if (write_encrypted_file("project/Makefiles/encrypted.bin", iv, hmac, ciphertext, ciphertext_len) != 0) {
        printf("Error writing encrypted file\n");
    } else {
        printf("Encryption successful. Output: encrypted.bin\n");
    }

    // Demo: Verify HMAC and decrypt
    unsigned char read_iv[IV_SIZE];
    unsigned char read_hmac[32];
    unsigned char *read_ciphertext;
    size_t read_ciphertext_len;

    if (read_encrypted_file("project/Makefiles/encrypted.bin", read_iv, read_hmac, &read_ciphertext, &read_ciphertext_len) == 0) {
        // Verify HMAC before decryption
        if (verify_hmac(read_ciphertext, read_ciphertext_len, key, read_hmac)) {
            unsigned char *decrypted = malloc(read_ciphertext_len);
            int decrypted_len = cbc_decrypt(read_ciphertext, read_ciphertext_len, key, read_iv, decrypted);
            
            if (decrypted_len > 0) {
                printf("Decryption successful. Length: %d bytes\n", decrypted_len);
                write_file("project/Makefiles/decrypted.txt", decrypted, decrypted_len);
            }
            free(decrypted);
        } else {
            printf("HMAC verification failed - file tampered!\n");
        }
        free(read_ciphertext);
    }

    // Cleanup
    free(file_data);
    free(ciphertext);

    return 0;
}
