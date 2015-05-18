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
    while(true) {
        // Establish connection with a director
        CONN *conn = establish_connection(diraddr, dirport);
        
        // Register with director
        if(register_with_dir(conn, service_type) != 0) {
            fprintf(stderr, "Error registering with director\n");
            exit(EXIT_FAILURE);
        }
        
        // THIS IS ALL TEMPORARY - WILL FIND FUNCTIONS FOR THIS
        int size = 0;
        // Wait for confirmation of collector
        char *receipt = recv_msg(conn, &size);
        if(*receipt != COLLECTOR_FOUND) {
            fprintf(stderr, "Error connecting to collector\n");
            free(receipt);
            SSL_free(conn->ssl);
            free(conn);
            // TEMP
            exit(EXIT_FAILURE);
            continue;
        }
        free(receipt);
        send_public_cert(conn);
        
        int key_length = 0;
        unsigned char iv[128];
        char *buf = recv_msg(conn, &size);
        unsigned char *key = decrypt_key((unsigned char*)buf, size, &key_length);
        // Received and decrypted key successfully
        send_msg(conn, NULL, 0, SUCCESS_RECEIPT);
        // Receive data
        buf = recv_msg(conn, &size);
        unsigned char msg[size];
        memcpy(msg, buf, size);
        memcpy(iv, buf + size - 128, 128);
        free(buf);
        int new_size = 0;
        unsigned char *decrypted = decrypt_data(msg, size, &new_size, key, key_length, iv);
        printf("%s\n", decrypted);
        int send_size = 0;
        char *result;
        if(service_type == 'a') {
            result = reverse_str((char *)decrypted);
            send_size = strlen(result) + 1;
        } else if(service_type == 'b') {
            result = find_mean((char *)decrypted, &send_size);
        } else {
            exit(EXIT_FAILURE);
        }
        free(decrypted);
        arc4random_buf(iv, 128);
        unsigned char *encrypted = encrypt_data((unsigned char *)result, send_size, &new_size, key, key_length, iv);
        buf = malloc(new_size + 128);
        memcpy(buf, encrypted, new_size);
        memcpy(buf + new_size, iv, 128);
        send_msg(conn, buf, new_size + 128, SUCCESS_RECEIPT);
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
    while(*str != '\0') {
        int index = 0;
        char *number = NULL;
        printf("Current number is %s\n", number);

        while(*(str + index) != ':' && *(str + index) != '\0') {
            number = realloc(number, index + 1);
            number[index] = str[index];
            printf("%c\n", *(number + index));
            index ++;
        }
        number = realloc(number, index + 1);
        number[index + 1] = '\0';
        printf("%s\n", number);
        n++;
        total += atoi(number);
        free(number);
        number = NULL;
        if(*(str + index) == '\0') {
            break;
        }
        str = str + index + 1;
        printf("Total is %i\n", total);
        printf("Number of items is %i\n", n);
        printf("String is at %c\n", *str);
    }
    double mean = ((double) total)/n;
    *send_size = sprintf(result, "%f", mean) + 1;
    return result;
}


