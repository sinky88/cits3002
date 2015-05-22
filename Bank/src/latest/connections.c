#include "bank.h"

int send_msg(void *ssl, char *buf, int size, char type)
{
    // Create header for message
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header = malloc(header_size);
    
    // Make sure integer is in network byte order
    uint32_t network_size = htonl(size);
    memcpy(header, &network_size, sizeof(uint32_t));
    memcpy(header + sizeof(uint32_t), &type, sizeof(char));
    
    // Send message header
    if(SSL_write(ssl, header, header_size) <= 0) {
        //perror("SSL write");
        fprintf(output_stream, "error: SSL write\n");
        free(header);
        return -1;
    }
    
    // If size is zero then no data to send
    if(size == 0) {
        return 1;
    }
    
    // Send data
    if(SSL_write(ssl, buf, size) <= 0) {
        //perror("SSL write");
        fprintf(output_stream, "error: SSL write\n");
        free(header);
        return -1;
    }
    
    free(header);
    return 1;
}

char *recv_msg(void *ssl, int *size, char *type)
{
    
    // Receive message header
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header = malloc(header_size);
    
    if(SSL_read(ssl, header, header_size) <= 0) {
        //perror("SSL read");
        fprintf(output_stream, "error: SSL read\n");
        free(header);
        return NULL;
    }
    char msg_type = 0;
    uint32_t network_size = 0;
    
    // Unpack integer and char
    memcpy(&network_size, header, sizeof(uint32_t));
    memcpy(&msg_type, header + sizeof(uint32_t), sizeof(char));
    
    // Make sure integer is in system byte order
    *size = ntohl(network_size);
    *type = msg_type;
    
    // If size is zero then no data to receive
    if(*size == 0) {
        return NULL;
    }
    
    // Receive data
    char *buf = malloc(*size);
    
    if(SSL_read(ssl, buf, *size) <= 0) {
        //perror("SSL read");
        fprintf(output_stream, "error: SSL write\n");
        free(header);
        free(buf);
        return NULL;
    }
    
    return buf;
}

int load_certs(SSL_INFO *conn)
{
    // Load own certificate
    if(!SSL_CTX_use_certificate_file(conn->ctx, BANK_CERT, SSL_FILETYPE_PEM) == 1) {
        //perror("certificate\n");
        fprintf(output_stream, "error: certificate\n");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, BANK_KEY, SSL_FILETYPE_PEM) == 1) {
        //perror("key\n");
        fprintf(output_stream, "error: key\n");
        return -1;
    }
    return 1;
}

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/*
 INIT_COMMUNICATION_ON_PORT(char *port) function returns an int referring to a socket that may be used for communications with clients. If the value it refers to is less than 0, we have an error
 */
int init_comm_on_port(char *port)
{
    int sockfd;  // listen on sock_fd
    struct addrinfo hints, *servinfo;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    
    //fill out serverinfo, rv checks for errors
    int rv;
    if ((rv = getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
        fprintf(output_stream, "getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }
    
    // DOUBLE    CHECK    THIS
    // loop through all the results from serverinfo and bind to the first we can
    struct addrinfo *p;
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                             p->ai_protocol)) == -1) {
            //perror("server: socket");
            fprintf(output_stream, "error: socket\n");
            continue;
        }
        
        int yes = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                       sizeof(int)) == -1) {
            //perror("setsockopt");
            fprintf(output_stream, "error: setsockopt\n");
            exit(1);
        }
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            //perror("server: bind");
            fprintf(output_stream, "error: bind\n");
            continue; }
        break;
    }
    
    // if unable to bind send error message
    if (p == NULL)  {
        fprintf(output_stream, "server: failed to bind\n");
        return -1;
    }
    
    // we're able to bind, no longer need servinfo
    freeaddrinfo(servinfo);
    
    //listen for connections and check for errors
    if (listen(sockfd, BACKLOG) == -1) {
        
        fprintf(output_stream, "listen");
        //perror("listen");
        return -1;
    }
    
     fprintf(output_stream, "waiting for connections...\n");
    
    return sockfd;
}

SSL_INFO *establish_ssl_conn()
{
    int err; //used for error checking
    
    // no return values for these functions,
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    
    // Blank connection structure
    SSL_INFO *conn = malloc(sizeof (SSL_INFO));
    
    // Initialise connection
    conn->ctx = SSL_CTX_new( SSLv3_method() ); //returns NULL if error can check error stack
    
    // Load certificates
    
    if ( (err = load_certs(conn) ) == -1) {
        //fatal error must close
        fprintf(output_stream, "error loading certs\n");
        //exit(EXIT_FAILURE);
        return NULL;
    }
    
    // Create new SSL structure
    conn->ssl = SSL_new(conn->ctx); // returns NULL if error can check error stack
    // Load in socket descriptor
 
    return conn;
}

/*
 SERVE_CLIENT(CONN *conn) function
 */
int serve_client(int listening_socket, SSL_INFO *conn)
{
    //int err; //checks for any errors
    socklen_t sin_size;
    struct sockaddr_storage their_addr;
    
    while(1) {  // main accept() loop
        sin_size = sizeof their_addr;
        
        /* ACCEPT CLIENT AND SPECIFY THEIR DETAILS */
        int new_fd;
        if( (new_fd = accept(listening_socket, (struct sockaddr *)&their_addr, &sin_size) ) == -1) {
            perror("accept");
            continue;
        }
        
        //get address of client being served
        char s[INET6_ADDRSTRLEN];
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
        
        fprintf(output_stream, "serving client %s\n", s);
        
        
        conn->bio=BIO_new(BIO_s_socket()); // NULL if call fails
        BIO_set_fd(conn->bio, new_fd, BIO_NOCLOSE);
        SSL_set_bio(conn->ssl, conn->bio, conn->bio);
        
        if(SSL_accept(conn->ssl) != 1) {
            //perror("SSL handshake");
            fprintf(output_stream, "error: SSL handshake\n");
            close(new_fd);
            continue;
        }
        
        
        fprintf(output_stream, "SSL handshake complete\n");
        
        /* FIND OUT WHAT CLIENT NEEDS AND SERVE THEM */
        
        char i_type;
        int i_size;
        char *rcvd_message = recv_msg(conn->ssl,&i_size, &i_type);
        //fprintf(output_stream, "received type: %c, size: %d\n", i_type, i_size);
        
        switch (i_type){
                
            case REQUEST_FOR_COIN:
            {
                int numcoins;
                if( (numcoins = atoi(rcvd_message)) == 0) {
                    fprintf(output_stream, "error: received incorrect input\n");
                    send_msg(conn->ssl, NULL, 0, NO_FUNDS_ERROR);
                    close(new_fd);
                    continue;
                }
                
                for(int i = 0; i < numcoins; i++) {
                    
                    int coinid = generate_coin();
                    if (coinid == -1) {
                        //error generating coin
                        send_msg(conn->ssl, NULL, 0, NO_FUNDS_ERROR);
                        close(new_fd);
                        continue;
                    }
                    
                    //largest possible coin id is 4294967295, which has 10 so we need 11 (null byte at end)
                    char *str = malloc( (10 + 1) * sizeof(char));
                    sprintf(str, "%i", coinid );
                    
                    
                    int length = strlen(str) + 1;
                    int after_length;
                    unsigned char *encrypted_cid = encrypt_string((unsigned char *)str, length, &after_length);
                    //printf("length = %d\n", after_length);
                    //printf("outputcoin= %s, len=%d\n", str, (int)strlen(str));
                    
                    send_msg(conn->ssl, (char *)encrypted_cid, after_length,SEND_COIN);
                }
                break;
            }
                
            case DEPOSIT_COIN:
            {
                char* str2 = decrypt_string((unsigned char *)rcvd_message, i_size);
                
                if(str2 == NULL) {
                    fprintf(stderr, "error!\n");
                    send_msg(conn->ssl, NULL, 0, DENIAL_OF_COIN);
                    close(new_fd);
                    continue;
                }
                
                int coinid = atoi(str2);
                if( coinid == 0) {
                    fprintf(stderr, "error!\n");
                    send_msg(conn->ssl, NULL, 0, DENIAL_OF_COIN);
                    close(new_fd);
                    continue;
                }
                
                int val = coin_value(coinid);

                if (val>0) send_msg(conn->ssl, NULL, 0, APPROVAL_OF_COIN);
                else send_msg(conn->ssl, NULL, 0, DENIAL_OF_COIN);
                
                break;
            }
                
            default:
                fprintf(output_stream, "Invalid message type received: %c", i_type);
                continue;
        }
        
        inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);
        
        fprintf(output_stream, "successfully served client connnecting from %s\n", s);
        
        //close connection
        close(new_fd);
        
        /* CLIENT HAS BEEN SERVED */
        
    }
    
    return 0;
}
