#include "collectors.h"

int init_conn(CONN *conn)
{
    // Initialise OpenSSL
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    SSL_library_init();
    
    // Set up the SSL context
    conn->ctx = SSL_CTX_new(SSLv3_method());
    return 0;
}

int load_certs(CONN *conn)
{
    // Load own certificate
    if(!SSL_CTX_use_certificate_file(conn->ctx, COL_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, COL_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key");
        return -1;
    }
    return 0;
}


CONN *establish_connection(char *addr, char *port)
{
    // Blank connection structure
    CONN *conn = malloc(sizeof (CONN));
    // Initialise connection
    init_conn(conn);
    // Load certificates
    load_certs(conn);
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx);
    
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    getaddrinfo(addr, port, &hints, &res);
    
    conn->sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    // Connect to server
    if(connect(conn->sd, res->ai_addr, res->ai_addrlen) != 0) {
        perror("connection");
    }
    
    // Set BIO into SSL structure
    conn->bio = BIO_new_socket(conn->sd, BIO_NOCLOSE);
    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    
    // Perform handshake
    if(SSL_connect(conn->ssl) != 1) {
        perror("handshake\n");
    }
    
    printf("Connection Established\n");
    return conn;
}

int register_with_dir(CONN *conn, char service_type, bool check)
{
    char msg_type;

    if(check) {
        msg_type = COLLECTOR_CHECK;
    } else {
        msg_type = NEW_COLLECTOR;
    }
    // Send handshake info
    send_msg(conn, &service_type, sizeof(char), msg_type);
    int size = 0;
    
    // Receive confirmation
    recv_msg(conn, &size, &msg_type);
    
    // Receive confirmation of available analyst
    
    char *receipt = recv_msg(conn, &size, &msg_type);
    if(*receipt == NO_ANALYST_FOUND) {
        fprintf(stderr, "No analysts found\n");
        free(receipt);
        exit(EXIT_FAILURE);
    }
    if(check) {
        printf("Found analyst\n");
        SSL_shutdown(conn->ssl);
        exit(EXIT_SUCCESS);
    }
    free(receipt);
    return 0;
}

char *recv_msg(CONN *conn, int *size, char *msg_type)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header  = malloc(sizeof(header_size));
    // Receive message header
    if(SSL_read(conn->ssl, header, header_size) <= 0) {
        perror("SSL read");
        free(header);
        exit(EXIT_FAILURE);
    }
    char type = 0;
    uint32_t network_size = 0;
    // Unpack integer and char
    memcpy(&network_size, header, sizeof(uint32_t));
    memcpy(&type, header + sizeof(uint32_t), sizeof(char));
    // Make sure integer is in system byte order
    *size = ntohl(network_size);
    *msg_type = type;
    // Error handling
    if(error_handler(type) != 0) {
        SSL_shutdown(conn->ssl);
        exit(EXIT_FAILURE);
    }
    if(*size == 0) {
        return NULL;
    }
    char *buf = malloc(*size);
    // Receive data
    if(SSL_read(conn->ssl, buf, *size) <= 0) {
        perror("SSL read");
        free(header);
        free(buf);
        exit(EXIT_FAILURE);
    }
    return buf;
}

int send_msg(CONN *conn, char *buf, int size, char type)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    // Create header for message
    char *header = malloc(header_size);
    // Make sure integer is in network byte order
    uint32_t network_size = htonl(size);
    memcpy(header, &network_size, sizeof(uint32_t));
    memcpy(header + sizeof(uint32_t), &type, sizeof(char));
    // Send message header
    if(SSL_write(conn->ssl, header, header_size) <= 0) {
        perror("SSL write");
        free(header);
        return CLOSED_CON;
    }
    // If size is zero then no data to send
    if(size == 0) {
        return 0;
    }
    // Send data
    if(SSL_write(conn->ssl, buf, size) <= 0) {
        perror("SSL write");
        free(header);
        return CLOSED_CON;
    }
    free(header);
    return 0;
}

int send_encrypt_msg(CONN *conn, char *buf, int size, char type, unsigned char *key, int key_length)
{
    unsigned char iv[128];
    int new_size;
    // Generate random IV
    arc4random_buf(iv, 128);
    // Encrypt the results
    unsigned char *encrypted = encrypt_data((unsigned char *)buf, size, &new_size, key, key_length, iv);
    // Check encryption was successful
    if(encrypted == NULL) {
        send_msg(conn, NULL, 0, ERROR_RECEIPT);
        // End connection with director
        return -1;
    }
    // Put results into buffer with IV
    buf = malloc(new_size + 128);
    memcpy(buf, encrypted, new_size);
    memcpy(buf + new_size, iv, 128);
    // Send the message to the collector
    send_msg(conn, buf, new_size + 128, type);
    return 0;
}

unsigned char *recv_encrypt_msg(CONN *conn, int *new_size, char *type, unsigned char *key, int key_length)
{
    int size;
    char *buf = recv_msg(conn, &size, type);
    unsigned char iv[128];
    unsigned char msg[size - 128];
    memcpy(msg, buf, size - 128);
    memcpy(iv, buf + size - 128, 128);
    free(buf);
    unsigned char *decrypted = decrypt_data(msg, size - 128, new_size, key, key_length, iv);
    return decrypted;
}


int recv_public_cert(CONN *conn)
{
    int size = 0;
    char msg_type;
    // Receive cert
    char *buf = recv_msg(conn, &size, &msg_type);
    // Open cert file for writing
    FILE *fp = fopen(ANA_CERT, "w");
    if(fp == NULL) {
        perror("Opening certificate");
        send_msg(conn, NULL, 0, CERT_ERROR);
        SSL_shutdown(conn->ssl);
        exit(EXIT_FAILURE);
    }
    fwrite(buf, size, 1, fp);
    fclose(fp);
    free(buf);
    return 0;
}

int error_handler(char msg_type)
{
    switch(msg_type){
        case ERROR_RECEIPT  :
            fprintf(stderr, "Analyst reports error receiving last message\n");
            return -1;
        case CLOSED_CON  :
            fprintf(stderr, "Connection to Analyst lost\n");
            return -1;
        case CERT_ERROR :
            fprintf(stderr, "Analyst reports error with certificate\n");
            return -1;
        case SUCCESS_CLOSE  :
            return 1;
        case DENIAL_OF_COIN :
            fprintf(stderr, "Analyst unable to process payment\n");
            return -1;
    }
    return 0;
}

int buy_ecent(CONN *conn, int amount)
{
    FILE *fp = fopen(ECENTS, "a");
    char *amount_str = malloc(32);
    sprintf(amount_str, "%d" , amount);
    send_msg(conn, amount_str, strlen(amount_str) + 1, REQUEST_FOR_COIN);
    for(int i = 0; i < 10; i ++) {
        char *buf;
        int size = 0;
        char msg_type;
        buf = recv_msg(conn, &size, &msg_type);
        fwrite(buf, size, 1, fp);
        free(buf);
    }
    fclose(fp);
    return 0;
}

int check_balance()
{
    int balance = 0;
    FILE *fp = fopen(ECENTS, "r");
    if(fp == NULL) {
        fprintf(stderr, "Error opening ecent file\n");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    int size = ftell(fp);
    balance = size / ECENT_SIZE;
    printf("Balance is %i \n", balance);
    fclose(fp);
    return balance;
}

int send_ecent(CONN *conn, unsigned char *key, int key_length)
{
    int file_size;
    int after_size;
    int size;
    // Read ecent file
    FILE *fp = fopen(ECENTS, "r+");
    if(fp == NULL) {
        fprintf(stderr, "Error opening ecent file\n");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, -ECENT_SIZE, SEEK_END);
    char *buf = malloc(ECENT_SIZE);
    fread(buf, ECENT_SIZE, 1, fp);
    FILE *temp = fopen("TEMP.file", "w");
    fwrite(buf, ECENT_SIZE, 1, temp);
    fclose(temp);
    char msg_type;
    // Generate random IV
    unsigned char iv[128];
    arc4random_buf(iv, 128);
    // Encrypt the data to send
    unsigned char *encrypted = encrypt_data((unsigned char *)buf, ECENT_SIZE, &after_size, key, key_length, iv);
    free(buf);
    // Check encryption was successful
    if(encrypted == NULL) {
        send_msg(conn, NULL, 0, ERROR_RECEIPT);
        exit(EXIT_FAILURE);
    }
    // Append the IV to the encrypted data to send
    buf = malloc(after_size + 128);
    memcpy(buf, encrypted, after_size);
    memcpy(buf + after_size, iv, 128);
    send_msg(conn, buf, after_size + 128, PAYMENT);
    free(buf);
    free(encrypted);
    recv_msg(conn, &size, &msg_type);
    if(error_handler(msg_type) >= 0) {
        truncate(ECENTS, file_size - ECENT_SIZE);
        
    } else {
        exit(EXIT_FAILURE);
    }
    fclose(fp);
    return 0;
}
