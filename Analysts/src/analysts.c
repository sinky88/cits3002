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
    char *bankaddr = "127.0.0.1";
    char *bankport = "6552";
    
    char service_type = DEFAULT_SERVICE;
    
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            case 't':
                if(optarg != NULL) {
                    service_type = optarg[0];
                } else {
                    fprintf(stderr, "Usage: %s [-t service] address port\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            default: fprintf(stderr, "Usage: %s [-t service] address port\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    // Check we have enough arguments
    if(argc - optind < 2) {
        fprintf(stderr, "Usage: %s [-t service] address port\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    // Set director port and address
    diraddr = argv[optind];
    dirport = argv[optind + 1];
    
    // Main loop
    while(true) {
        // Establish connection with a director
        CONN *conn = establish_connection(diraddr, dirport);
        
        // Register with director
        if(register_with_dir(conn, service_type) != 0) {
            fprintf(stderr, "Error registering with director\n");
            exit(EXIT_FAILURE);
        }
        int size = 0;
        char msg_type;

        // Wait for confirmation of collector
        char *receipt = recv_msg(conn, &size, &msg_type);
        if(*receipt != COLLECTOR_FOUND) {
            fprintf(stderr, "Error connecting to collector\n");
            free(receipt);
            SSL_free(conn->ssl);
            free(conn);
            continue;
        }
        free(receipt);
        send_public_cert(conn);
        
        int key_length = 0;
        unsigned char iv[128];
        char *buf = recv_msg(conn, &size, &msg_type);
        unsigned char *key = decrypt_key((unsigned char*)buf, size, &key_length);
        // Check if key was decrypted successfully
        if(key == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            continue;
        }
        free(buf); // HMMMMMMMMMMMM
        // Send confirmation of success
        send_msg(conn, NULL, 0, SUCCESS_RECEIPT);
        // Recv the ecent payment
        buf = recv_msg(conn, &size, &msg_type);
        
        // Copy encrypted data and IV into seperate buffers
        unsigned char msg[size];
        memcpy(msg, buf, size);
        memcpy(iv, buf + size - 128, 128);
        free(buf);
        
        int new_size = 0;
        unsigned char *decrypted = decrypt_data(msg, size, &new_size, key, key_length, iv);
        
        // Check if decryption was succesful
        if(decrypted == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            continue;
        }

        // Establish connection with the bank
        CONN *conn2 = establish_connection(bankaddr, bankport);
        
        if(deposit_ecent(conn2, (char *)decrypted, new_size) < 0) {
            SSL_shutdown(conn2->ssl);
            SSL_free(conn2->ssl);
            free(conn2);
            // Send failure message to collector
            send_msg(conn, NULL, 0, DENIAL_OF_COIN);
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
            free(conn);
            free(decrypted);
            continue;
        }
        
        // Shutdown connection to bank
        SSL_shutdown(conn2->ssl);
        SSL_free(conn2->ssl);
        free(conn2);
        
        free(decrypted);
        
        // Send confirmation of success to collector
        send_msg(conn, NULL, 0, APPROVAL_OF_COIN);
        
        // Receive data
        buf = recv_msg(conn, &size, &msg_type);
        // Copy encrypted data and IV into seperate buffers
        unsigned char msg2[size];
        memcpy(msg2, buf, size);
        memcpy(iv, buf + size - 128, 128);
        free(buf);
        
        decrypted = decrypt_data(msg, size, &new_size, key, key_length, iv);
        // Check if decryption was succesful
        if(decrypted == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            // End connection with director
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
            free(conn);
            continue;
        }
        printf("%s\n", decrypted);
        
        // Analyse the data
        int send_size = 0;
        char *result;
        if(service_type == 'a') {
            result = reverse_str((char *)decrypted);
            send_size = strlen(result) + 1;
        } else if(service_type == 'b') {
            result = find_mean((char *)decrypted, &send_size);
        } else {
            continue;
        }
        free(decrypted);
        // Generate random IV
        arc4random_buf(iv, 128);
        // Encrypt the results
        unsigned char *encrypted = encrypt_data((unsigned char *)result, send_size, &new_size, key, key_length, iv);
        // Check encryption was successful
        if(encrypted == NULL) {
            send_msg(conn, NULL, 0, ERROR_RECEIPT);
            // End connection with director
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
            free(conn);
            continue;
        }
        // Put results into buffer with IV
        buf = malloc(new_size + 128);
        memcpy(buf, encrypted, new_size);
        memcpy(buf + new_size, iv, 128);
        // Send the message to the collector
        send_msg(conn, buf, new_size + 128, SUCCESS_RECEIPT);
        // End connection with director
        SSL_shutdown(conn->ssl);
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

char *find_mean(char *str, int *send_size)
{
    char *result = malloc(30);
    int total = 0;
    int n = 0;
    // Loop through string
    while(*str != '\0') {
        int index = 0;
        char *number = NULL;
        
        // Loop until we reach ':' character
        while(*(str + index) != ':' && *(str + index) != '\0') {
            // Allocate memory in number string
            number = realloc(number, index + 1);
            // Set number in string
            number[index] = str[index];
            index ++;
        }
        number = realloc(number, index);
        number[index] = '\0';
        n++;
        total += atoi(number);
        free(number);
        number = NULL;
        if(*(str + index) == '\0') {
            break;
        }
        str = str + index + 1;
    }
    double mean = ((double) total)/n;
    *send_size = sprintf(result, "%f", mean) + 1;
    return result;
}
char *find_maxsize(char *str)
{
    
    char *result = NULL;
    int place=0,length=0, maxlength=0;
    
    for(int i=0;i<strlen(str);i++)
    {
        if(str[i]==' ')
        {
            if (length>maxlength)
            {
                maxlength = length;
                place = i - length;
            }
            length = 0;
        }
        else
            length++;
    } 
    
    if (length>maxlength)
    {
        maxlength = length;
        place = strlen(str) - length;
    }
    for(int ii = 0; ii<maxlength; ii++)
        *result = str[place+ii];
        return result;
}


