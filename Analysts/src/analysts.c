#include "analysts.h"

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
    //  TODO Initialise any global variables
    // Check we have enough arguments
    if(argc < 3) {
        fprintf(stderr, "Usage: %s address port\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Set director port and address
    diraddr = argv[1];
    dirport = argv[2];
    
    // No options right now
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
        }
    }
    
    while(true) {
        // Establish connection with a director
        CONN *conn = establish_connection(diraddr, dirport);
        
        // Register with director
        if(register_with_dir(conn, DEFAULT_SERVICE) != 0) {
            fprintf(stderr, "Error registering with director\n");
            exit(EXIT_FAILURE);
        }
        
        // THIS IS ALL TEMPORARY - WILL FIND FUNCTIONS FOR THIS
        MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
        SSL_read(conn->ssl, header, sizeof(MSG_HEADER));
        if(header->msg_type != COLLECTOR_FOUND) {
            fprintf(stderr, "Error connecting to collector\n");
            free(header);
            SSL_free(conn->ssl);
            free(conn);
            continue;
        }
        send_public_cert(conn);
        
        int size = 0;
        unsigned char *buf = recv_msg(conn, &size);
        int key_length = 0;
        unsigned char *key = decrypt_key(buf, size, &key_length);
        // Received and decrypted key successfully
        header->msg_type = SUCCESS_RECEIPT;
        header->size = sizeof("Nothing");
        SSL_write(conn->ssl, header, sizeof(MSG_HEADER));
        SSL_write(conn->ssl, "Nothing", header->size);
        // Receive data
        SSL_read(conn->ssl, header, sizeof(MSG_HEADER));
        buf = malloc(header->size);
        unsigned char iv[128];
        SSL_read(conn->ssl, buf, header->size);
        unsigned char msg[header->size];
        memcpy(msg, buf, header->size);
        memcpy(iv, buf + header->size - 128, 128);
        int new_size = 0;
        unsigned char *decrypted = decrypt_data(msg, header->size, &new_size, key, key_length, iv);
        free(header);
        printf("%s\n", decrypted);
        SSL_free(conn->ssl);
        free(conn);

    }
    return result;
}

char *reverse_str(char *str)
{
    int size = strlen(str);
    char *reverse = malloc(size + 1);
    for(int i = 0; i < size; i ++) {
        reverse[i] = str[size - i - 1];
    }
    reverse[size] = '\0';
    return reverse;
}


