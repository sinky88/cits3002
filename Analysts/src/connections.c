#include "analysts.h"

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
    if(!SSL_CTX_use_certificate_file(conn->ctx, ANA_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, ANA_KEY, SSL_FILETYPE_PEM) == 1) {
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
        exit(EXIT_FAILURE);
    }
    
    // Set BIO into SSL structure
    conn->bio = BIO_new_socket(conn->sd, BIO_NOCLOSE);
    SSL_set_bio(conn->ssl, conn->bio, conn->bio);
    
    // Perform handshake
    if(SSL_connect(conn->ssl) != 1) {
        perror("handshake\n");
        exit(EXIT_FAILURE);
    }
    
    printf("Connection Established\n");
    return conn;
}

int register_with_dir(CONN *conn, char service_type)
{
    // Send handshake info
    send_msg(conn, &service_type, sizeof(char), NEW_ANALYST);
    int size = 0;
    char msg_type;
    // Receive confirmation
    recv_msg(conn, &size, &msg_type);
    
    return 0;
}

char *recv_msg(CONN *conn, int *size, char *type)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header  = malloc(sizeof(header_size));
    // Receive message header
    if(SSL_read(conn->ssl, header, header_size) <= 0) {
        fprintf(stderr, "Lost connection with the Director\n");
        send_msg(conn, NULL, 0, ERROR_RECEIPT);
        free(header);
        exit(EXIT_FAILURE);
    }
    char msg_type = 0;
    uint32_t network_size = 0;
    // Unpack integer and char
    memcpy(&network_size, header, sizeof(uint32_t));
    memcpy(&msg_type, header + sizeof(uint32_t), sizeof(char));
    // Make sure integer is in system byte order
    *size = ntohl(network_size);
    *type = msg_type;

    // Error handling
    if(error_handler(msg_type) != 0) {
        SSL_shutdown(conn->ssl);
        exit(EXIT_FAILURE);
    }
    if(*size == 0) {
        return NULL;
    }
    char *buf = malloc(*size);
    // Receive data
    if(SSL_read(conn->ssl, buf, *size) <= 0) {
        fprintf(stderr, "Lost connection with the Director\n");
        send_msg(conn, NULL, 0, ERROR_RECEIPT);
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


int send_public_cert(CONN *conn)
{
    // Open public certificate for reading
    FILE *fp = fopen(ANA_CERT, "r");
    if(fp == NULL) {
        perror("Opening certificate");
        send_msg(conn, NULL, 0, CERT_ERROR);
        SSL_shutdown(conn->ssl);
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    rewind(fp);
    char *buf = malloc(size);
    fread(buf, size, 1, fp);
    fclose(fp);
    send_msg(conn, buf, size, SUCCESS_RECEIPT);
    return 0;
}

int error_handler(char msg_type)
{
    switch(msg_type){
        case ERROR_RECEIPT  :
            fprintf(stderr, "Collector reports error receiving last message\n");
            return -1;
        case CLOSED_CON  :
            fprintf(stderr, "Connection to director lost\n");
            return -1;
        case CERT_ERROR :
            fprintf(stderr, "Collector reports error with certificate\n");
            return -1;
        case DENIAL_OF_COIN :
            fprintf(stderr, "Bank denied coin deposit\n");
            return -1;
        case SUCCESS_CLOSE  :
            return 1;
    }
    return 0;
}

int deposit_ecent(CONN *conn, char *buf, int size)
{
    send_msg(conn, buf, size, DEPOSIT_COIN);
    int new_size;
    char msg_type;
    recv_msg(conn, &new_size, &msg_type);
    printf("Return message type %c\n", msg_type);
    return error_handler(msg_type);
}



