
#include "collectors.h"

unsigned char *gen_rand_key(int *keylength)
{
    unsigned char *key;
    RSA *rsa = RSA_generate_key(128, 3, 0, 0);
    BIO *keybio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(keybio, rsa, NULL, NULL, 0, NULL, NULL);
    *keylength = BIO_pending(keybio);
    key = calloc(*keylength, 1);
    BIO_read(keybio, key, *keylength);
    BIO_free_all(keybio);
    RSA_free(rsa);
    return key;
}

unsigned char *encrypt_key(unsigned char *key, int keylength)
{
    X509 *cert = createX509(ANA_CERT);
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    RSA *rsa2 = EVP_PKEY_get1_RSA(pubkey);
    if(rsa2 == NULL) {
        perror("Unable to create rsa structure");
        return NULL;
    }
    int size = RSA_size(rsa2);
    printf("RSA size is %i\n", size);
    unsigned char *encrypted = malloc(size);
    RSA_public_encrypt(keylength, key, encrypted, rsa2, RSA_PKCS1_PADDING);
    EVP_PKEY_free(pubkey);
    return encrypted;
}

X509 *createX509(char *filename)
{
    FILE *fp = fopen(filename,"rb");
    
    if(fp == NULL) {
        perror("Unable to open file");
        return NULL;
    }
    
    X509 *x= X509_new();
    if(x == NULL) {
        perror("Unable to create X509 structure");
        return NULL;
    }
    
    x = PEM_read_X509(fp, &x, NULL, NULL);
    if(x == NULL) {
        perror("Unable to read public key");
        return NULL;
    }
    return x;
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
