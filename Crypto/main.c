
#include <stdio.h>
#include <string.h>
#include <stdint.h>


#include "api.h"
#include "encrypt.c"
#include "decrypt.c"


int main() {
    printf("Testing Ascon AEAD Implementation\n");
    printf("Version: %s\n", CRYPTO_VERSION);
    
    
    unsigned char key[CRYPTO_KEYBYTES] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    
    unsigned char nonce[CRYPTO_NPUBBYTES] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };
    
    unsigned char ad[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    
    unsigned char plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    size_t ad_len = sizeof(ad);
    size_t pt_len = sizeof(plaintext);
    
    // Buffer for ciphertext (plaintext + tag)
    unsigned char ciphertext[sizeof(plaintext) + CRYPTO_ABYTES];
    unsigned long long clen = 0;
    
    // Buffer for decrypted plaintext
    unsigned char decrypted[sizeof(plaintext)];
    unsigned long long dlen = 0;
    
    // Encrypt
    printf("\n=== Encryption ===\n");
    int encrypt_result = crypto_aead_encrypt(
        ciphertext, &clen,
        plaintext, pt_len,
        ad, ad_len,
        NULL,  // nsec (unused)
        nonce,
        key
    );
    
    printf("Encryption result: %d\n", encrypt_result);
    printf("Ciphertext length: %llu\n", clen);
    
    // Decrypt
    printf("\n=== Decryption ===\n");
    int decrypt_result = crypto_aead_decrypt(
        decrypted, &dlen,
        NULL,  // nsec (unused)
        ciphertext, clen,
        ad, ad_len,
        nonce,
        key
    );
    
    printf("Decryption result: %d\n", decrypt_result);
    printf("Decrypted length: %llu\n", dlen);
    
    // Verify
    printf("\n=== Verification ===\n");
    if (decrypt_result == 0) {
        if (dlen == pt_len && memcmp(plaintext, decrypted, pt_len) == 0) {
            printf("SUCCESS: Decrypted text matches original!\n");
        } else {
            printf("FAIL: Decrypted text doesn't match!\n");
        }
    } else {
        printf("FAIL: Decryption failed!\n");
    }
    
    // Test with modified ciphertext (should fail)
    printf("\n=== Tampering Test ===\n");
    ciphertext[0] ^= 0x01;  // Flip one bit
    decrypt_result = crypto_aead_decrypt(
        decrypted, &dlen,
        NULL,
        ciphertext, clen,
        ad, ad_len,
        nonce,
        key
    );
    
    if (decrypt_result != 0) {
        printf("SUCCESS: Tampering detected (returned %d)\n", decrypt_result);
    } else {
        printf("FAIL: Tampering not detected!\n");
    }
    
    return 0;
}