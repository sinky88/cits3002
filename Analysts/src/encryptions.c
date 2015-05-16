
#include "analysts.h"
unsigned char *decrypt_key(unsigned char *encrypted, int length, int *key_length)
{
    FILE *fp = fopen(ANA_KEY, "r");
    if(fp == NULL) {
        perror("Unable to open file");
        return NULL;
    }
    RSA *rsa = NULL;
    PEM_read_RSAPrivateKey(fp, &rsa, NULL, 0);
    if(rsa == NULL) {
        perror("Unable to create rsa structure");
        return NULL;
    }
    unsigned char *decrypted = malloc(RSA_size(rsa));
    *key_length = RSA_private_decrypt(length, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if(decrypted == NULL) {
        fprintf(stderr, "Decrypting key failed\n");
    }
    fclose(fp);
    return decrypted;
}

unsigned char *encrypt_data(unsigned char *buf, int size, int *after_size, unsigned char *key, int keylength, unsigned char *iv)
{
    int len;
    unsigned char *encrypted = malloc(size + 32);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, encrypted, &len, buf, size);
    *after_size = len;
    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);
    *after_size += len;
    EVP_CIPHER_CTX_free(ctx);
    return encrypted;
}

unsigned char *decrypt_data(unsigned char *buf, int size, int *after_size, unsigned char *key, int keylength, unsigned char *iv)
{
    int len;
    unsigned char *decrypted = malloc(size);
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, decrypted, &len, buf, size);
    *after_size = len;
    EVP_DecryptFinal_ex(ctx, decrypted + len, &len);
    *after_size += len;
    EVP_CIPHER_CTX_free(ctx);
    return decrypted;
}
