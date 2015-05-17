#include "collectors.h"

/*
 CITS3002 Project 2015
 Name(s):             Benjamin Sinclair
 Student number(s):   20153423
 Date:
 */


int main(int argc, char *argv[])
{
    int result  = 0;
    char *diraddr;
    char *dirport;
    unsigned char *message;
    int message_size;
    // Check we have enough arguments
    if(argc < 4) {
        fprintf(stderr, "Usage: %s address port message\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Set director port and address
    diraddr = argv[1];
    dirport = argv[2];
    
    message_size = strlen(argv[3]) + 1;
    message = (unsigned char*) argv[3];
    
    // No options right now
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
        }
    }
    
    // Establish connection with a director
    CONN *conn = establish_connection(diraddr, dirport);
    
    // Register with director
    if(register_with_dir(conn, DEFAULT_SERVICE) != 0) {
        fprintf(stderr, "Unable to register with director\n");
        exit(EXIT_FAILURE);
    }
    recv_public_cert(conn);
    // THIS IS ALL TEMPORARY - WILL FIND FUNCTIONS FOR THIS
    int key_length;
    unsigned char *key = gen_rand_key(&key_length);
    unsigned char *encrypted = encrypt_key(key, key_length);
    send_msg(conn, (char *)encrypted, 256, SUCCESS_RECEIPT);
    free(encrypted);
    int after_size;
    int size;
    // Do a read because it's our turn
    char *buf = recv_msg(conn, &after_size);
    unsigned char iv[128];
    arc4random_buf(iv, 128);
    encrypted = encrypt_data(message, message_size, &after_size, key, key_length, iv);
    buf = malloc(after_size + 128);
    memcpy(buf, encrypted, after_size);
    memcpy(buf + after_size, iv, 128);
    send_msg(conn, buf, after_size + 128, SUCCESS_RECEIPT);
    free(buf);
    // Receive data
    buf = recv_msg(conn, &size);
    unsigned char msg[size];
    memcpy(msg, buf, size);
    memcpy(iv, buf + size - 128, 128);
    int new_size = 0;
    unsigned char *decrypted = decrypt_data(msg, size, &new_size, key, key_length, iv);
    printf("%s\n", decrypted);
    SSL_free(conn->ssl);
    free(conn);
    return result;
}



