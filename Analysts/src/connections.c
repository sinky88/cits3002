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

int register_with_dir(CONN *conn, char service_type)
{
    // Set up handshake info
    MSG_HEADER *header;
    header = malloc(sizeof(MSG_HEADER));
    header->msg_type = NEW_ANALYST;
    header->size = 0;
    if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
        perror("SSL write");
        return -1;
    }

    // Send service type
    if(SSL_write(conn->ssl, &service_type, sizeof(service_type)) <= 0) {
        perror("SSL write");
        return -1;
    }

    // Receive message confirmation
    if(SSL_read(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
        perror("SSL read");
        return -1;
    }
    
    if(header->msg_type != SUCCESS_RECEIPT) {
        fprintf(stderr, "Error connecting to director\n");
    }
    
    return 0;
}

char *recv_msg(CONN *conn, int *size)
{
    MSG_HEADER *header  = malloc(sizeof(MSG_HEADER));
    // Receive message header
    if(SSL_read(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
        perror("SSL read");
        free(header);
        exit(EXIT_FAILURE);
    }
    *size = header->size;
    printf("received type %i\n", header->msg_type);

    // TODO add more error handling
    if(header->msg_type != SUCCESS_RECEIPT) {
        printf("%i\n", header->msg_type);
        fprintf(stderr, "Error receiving message\n");
        exit(EXIT_FAILURE);
        // bad stuff
    }
    if(header->size == 0) {
        return NULL;
    }
    char *buf = malloc(*size);
    // Receive data
    if(SSL_read(conn->ssl, buf, *size) <= 0) {
        perror("SSL read");
        free(header);
        free(buf);
        return NULL;
    }
    
    return buf;
}

int send_msg(CONN *conn, char *buf, int size, char type)
{
    MSG_HEADER *header  = malloc(sizeof(MSG_HEADER));
    header->msg_type = type;
    header->size = size;
    // Send message header
    if(SSL_write(conn->ssl, header, sizeof(MSG_HEADER)) <= 0) {
        perror("SSL write");
        free(header);
        return -1;
    }
    if(header->size == 0) {
        return 0;
    }
    // Send data
    if(SSL_write(conn->ssl, buf, header->size) <= 0) {
        perror("SSL write");
        return -1;
    }
    
    return 0;
}


int send_public_cert(CONN *conn)
{
    MSG_HEADER *header = malloc(sizeof(MSG_HEADER));
    FILE *fp = fopen(ANA_CERT, "r");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    rewind(fp);
    char *buf = malloc(size);
    fread(buf, size, 1, fp);
    fclose(fp);
    header->size = size;
    header->msg_type  = SUCCESS_RECEIPT;
    SSL_write(conn->ssl, header, sizeof(MSG_HEADER));
    SSL_write(conn->ssl, buf, size);
    return 0;
}




