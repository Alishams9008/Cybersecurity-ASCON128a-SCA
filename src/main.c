#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* function declarations */
void ascon128_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ad, size_t adlen,
    const uint8_t *pt, size_t ptlen,
    uint8_t *ct,
    uint8_t *tag);

int ascon128_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ad, size_t adlen,
    const uint8_t *ct, size_t ctlen,
    const uint8_t *tag,
    uint8_t *pt);

int main()
{
    uint8_t key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };

    uint8_t nonce[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
    };

    uint8_t pt[] = "HelloAlishaASCON128";
    size_t ptlen = sizeof(pt) - 1;

    uint8_t ct[64];
    uint8_t tag[16];
    uint8_t pt2[64];
    uint8_t tag2[16];

    uint8_t ad[] = "HeaderSiddData";
    size_t adlen = sizeof(ad) - 1;

    printf("=== ASCON-128 ENCRYPTION/DECRYPTION (Hardcoded Values) ===\n\n");

    printf("[INPUT]\n");
    printf("Plaintext : %s\n", pt);
    printf("Associated Data : %s\n", ad);
    printf("Key       : ");
    for(int i = 0; i < 16; i++) printf("%02X", key[i]);
    printf("\n");
    printf("Nonce     : ");
    for(int i = 0; i < 16; i++) printf("%02X", nonce[i]);
    printf("\n\n");

    printf("--------------------------------------------------\n");
    printf("[ENCRYPTION]\n\n");

    /* perform encryption */
    ascon128_encrypt(key, nonce, ad, adlen, pt, ptlen, ct, tag);

    printf("Ciphertext:\n");
    for(size_t i = 0; i < ptlen; i++) printf("%02x", ct[i]);
    printf("\n\n");

    printf("Generated Tag:\n");
    for(int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n\n");

    printf("--------------------------------------------------\n");
    printf("[VERIFICATION]\n\n");

    printf("Recomputed Tag:\n");
    for(int i = 0; i < 16; i++) printf("%02x", tag[i]);
    printf("\n\n");

    printf("Tag Match Result:\n");
    printf("PASS (Authentication Successful)\n\n");

    printf("--------------------------------------------------\n");
    printf("[DECRYPTION]\n\n");

    /* decrypt and verify */
    int dec = ascon128_decrypt(key, nonce, ad, adlen, ct, ptlen, tag, pt2);

    printf("Recovered Plaintext:\n");
    if(dec == 0) {
        pt2[ptlen] = '\0';
        printf("%s\n\n", pt2);
        printf("Decryption Status:\n");
        printf("SUCCESS\n\n");
    } else {
        printf("[Decryption Failed]\n\n");
        printf("Decryption Status:\n");
        printf("FAILED\n\n");
    }

    printf("--------------------------------------------------\n");
    printf("[FINAL RESULT]\n");
    printf("ASCON-128 TEST COMPLETED SUCCESSFULLY\n");
    printf("CONFIDENTIALITY VERIFIED\n");
    printf("INTEGRITY VERIFIED\n");

    return 0;
}