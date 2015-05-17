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
    int keylength;
    unsigned char *key = gen_rand_key(&keylength);
    unsigned char *encrypted = encrypt_key(key, keylength);
    MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
    header->msg_type = SUCCESS_RECEIPT;
    header->size = 256;
    
    SSL_write(conn->ssl, header, sizeof(MSG_HEADER));

    SSL_write(conn->ssl, encrypted, 256);

    // Our turn to do a read, deal with this later
    SSL_read(conn->ssl, header, sizeof(MSG_HEADER));
    char *buf;
    
    int after_size;
    unsigned char iv[128];
    arc4random_buf(iv, 128);
    unsigned char *msg = encrypt_data(message, message_size, &after_size, key, keylength, iv);
    header->size = after_size + 128;
    buf = malloc(header->size);
    memcpy(buf, msg, after_size);
    memcpy(buf + after_size, iv, 128);
    SSL_write(conn->ssl, header, sizeof(MSG_HEADER));
    SSL_write(conn->ssl, buf, header->size);
    return result;
}



