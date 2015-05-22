#include "bank.h"

//retruns null if error
unsigned char *encrypt_string(unsigned char *str, int length, int *after_length)
{
    X509 *cert = createX509(BANK_CERT);
    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    RSA *rsa2 = EVP_PKEY_get1_RSA(pubkey);
    if(rsa2 == NULL) {
        perror("Unable to create rsa structure");
        printf("Unable to create rsa structure\n");
        return NULL;
    }
    int size = RSA_size(rsa2);
    //printf("RSA size is %i\n", size);
    
    unsigned char *encrypted = malloc(size);
    *after_length = RSA_public_encrypt(length, str, encrypted, rsa2, RSA_PKCS1_PADDING);
    EVP_PKEY_free(pubkey);

    return encrypted;
}

char *decrypt_string(unsigned char *encrypted, int length)
{

    FILE *fp = fopen(BANK_KEY, "r");
    if(fp == NULL) {
        perror("Unable to open file");
        printf("Unable to open file\n");
        return NULL;
    }
    RSA *rsa = NULL;
    PEM_read_RSAPrivateKey(fp, &rsa, NULL, 0);
    if(rsa == NULL) {
        perror("Unable to create rsa structure");
        printf("Unable to open file\n");
        return NULL;
    }
    unsigned char *decrypted = malloc(RSA_size(rsa));
    
    RSA_private_decrypt(length, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    
    if(decrypted == NULL) {
        fprintf(stderr, "Decrypting key failed\n");
        printf("Unable to open file\n");
    }
    fclose(fp);
    
    char *str = (char *) decrypted;
    return str;
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
