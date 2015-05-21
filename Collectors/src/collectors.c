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
    char *serveraddr;
    char *serverport;
    char service_type = DEFAULT_SERVICE;
    char server_type = DEFAULT_SERVER;
    unsigned char *message;
    int message_size;
    
    
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            case 's':
                if(optarg != NULL) {
                    server_type = optarg[0];
                } else {
                    fprintf(stderr, USAGE, argv[0]);
                    exit(EXIT_FAILURE);
                }
            case 't':
                if(optarg != NULL) {
                    service_type = optarg[0];
                } else {
                    fprintf(stderr, USAGE, argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            default: fprintf(stderr, USAGE, argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    // Check we have enough arguments
    if(argc - optind < 3) {
        fprintf(stderr, USAGE, argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // Set director port and address
    serveraddr = argv[optind];
    serverport = argv[optind + 1];

    // Establish connection with a director
    CONN *conn = establish_connection(serveraddr, serverport);
    
    buy_ecent(conn);
    
    exit(0);
    
    if(server_type == 'd') {
        message_size = strlen(argv[optind + 2]) + 1;
        message = (unsigned char*) argv[optind + 2];
        // Register with director
        if(register_with_dir(conn, service_type) != 0) {
            fprintf(stderr, "Unable to register with director\n");
            exit(EXIT_FAILURE);
        }
        recv_public_cert(conn);
        
        int key_length;
        // Generate key for communication
        unsigned char *key = gen_rand_key(&key_length);
        // Encrypt the key
        unsigned char *encrypted = encrypt_key(key, key_length);
        // Check encryption was successful
        if(encrypted == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            exit(EXIT_FAILURE);
        }
        // Send the key
        send_msg(conn, (char *)encrypted, 256, SUCCESS_RECEIPT);
        free(encrypted);
        int after_size;
        int size;
        // Do a read because it's our turn
        char *buf = recv_msg(conn, &after_size);
        // Generate random IV
        unsigned char iv[128];
        arc4random_buf(iv, 128);
        // Encrypt the data to send
        encrypted = encrypt_data(message, message_size, &after_size, key, key_length, iv);
        // Check encryption was successful
        if(encrypted == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            exit(EXIT_FAILURE);
        }
        // Append the IV to the encrypted data to send
        buf = malloc(after_size + 128);
        memcpy(buf, encrypted, after_size);
        memcpy(buf + after_size, iv, 128);
        send_msg(conn, buf, after_size + 128, SUCCESS_RECEIPT);
        free(buf);
        // Receive analysed data
        buf = recv_msg(conn, &size);
        unsigned char msg[size];
        memcpy(msg, buf, size);
        memcpy(iv, buf + size - 128, 128);
        int new_size = 0;
        // Decrypt the data
        unsigned char *decrypted = decrypt_data(msg, size, &new_size, key, key_length, iv);
        // Check if decryption was succesful
        if(decrypted == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            exit(EXIT_FAILURE);
        }
        printf("%s\n", decrypted);
        // Send close message
        send_msg(conn, NULL, 0, SUCCESS_CLOSE);
    }
    if(server_type == 'b') {
        // Do bank stuff
    }
    SSL_free(conn->ssl);
    free(conn);
    return result;
}



