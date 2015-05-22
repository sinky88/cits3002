#include "directors.h"

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
    if(!SSL_CTX_use_certificate_file(conn->ctx, DIR_CERT, SSL_FILETYPE_PEM) == 1) {
        perror("certificate\n");
        return -1;
    }
    // Load private key
    if(!SSL_CTX_use_PrivateKey_file(conn->ctx, DIR_KEY, SSL_FILETYPE_PEM) == 1) {
        perror("key\n");
        return -1;
    }
    return 0;
}

// Function to wait for an SSL connection from analyst or collector

int *wait_for_connection(char *port)
{
    int listen_socket;
    struct sockaddr_storage client_addr;
    socklen_t addr_len;
    
    int yes=1;
    
    // Set up structures for TCP connection
    struct addrinfo hints, *res;
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    
    if (getaddrinfo(NULL, port, &hints, &res) != 0) {
        fprintf(stderr, "error\n");
        exit(EXIT_FAILURE);
    }
    
    // Make a socket for listening
    listen_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    
    
    // Make sure port is available
    if (setsockopt(listen_socket,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int)) == -1) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    // Bind it to the port
    if(bind(listen_socket, res->ai_addr, res->ai_addrlen) == -1) {
        close(listen_socket);
        perror("bind");
        exit(EXIT_FAILURE);
    }
    
    // Free res pointer
    freeaddrinfo(res);
    
    // Listen to the port
    if (listen(listen_socket, BACKLOG) == -1) {
        perror("listening");
        exit(EXIT_FAILURE);
    }
    printf("Listening for connection on port %s\n", port);
    
    
    // Set timeout values
    struct timeval *timeout = malloc(sizeof(struct timeval));
    
    timeout->tv_sec  = 0;
    timeout->tv_usec =  TIMEOUT;
    
    // Create list for connected clients
    INFO *info = malloc(sizeof(INFO));
    info->client_id = -1;
    node_t *analyst_list = create_list(info);
    node_t *collector_list = create_list(info);
    
    int client_id = 0;
    
    
    // Main loop
    while(true) {
        
        fd_set read_fds;
        
        FD_ZERO(&read_fds);
        
        // Add the listening socket to the read set
        FD_SET(listen_socket, &read_fds);
        
        // Run select on the listening socket
        if(select(listen_socket + 1, &read_fds, NULL, NULL, timeout) == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        }
        
        // Check if the listen socket is ready for reading
        if(FD_ISSET(listen_socket, &read_fds)) {
            // Accept new connection
            int sd = accept(listen_socket, (struct sockaddr *)&client_addr, &addr_len);
            if(sd == -1) {
                fprintf(stderr, "Error accepting tcp connection\n");
            } else {
                printf("Tcp connection established\n");
                // Blank connection structure
                CONN *conn = malloc(sizeof (CONN));
                // Initialise connection
                init_conn(conn);
                // Load certificates
                load_certs(conn);
                // Create new SSL structure
                conn->ssl = SSL_new(conn->ctx);
                // Set BIO into SSL structure
                BIO *bio = BIO_new_socket(sd, BIO_NOCLOSE);
                SSL_set_bio(conn->ssl, bio, bio);
                // Perform handshake
                if(SSL_accept(conn->ssl) != 1) {
                    perror("SSL handshake");
                    exit(EXIT_FAILURE);
                }
                printf("SSL handshake complete\n");
                // Register new client
                register_client(conn, analyst_list, collector_list, &client_id);
            }
        }
        service_collectors(collector_list);
    }
    return 0;
}

int register_client(CONN *conn, node_t *analyst_list, node_t *collector_list, int *client_id)
{
    int size = 0;
    char msg_type = 0;
    bool error = false;
    
    char *service_type = recv_msg(conn->ssl, &size, &msg_type, &error);
    if(error == true) {
        msg_type = CLOSED_CON;
    }
    // Check what kind of connection we have
    if(msg_type == NEW_ANALYST) {
        INFO *analyst = malloc(sizeof(INFO));
        printf("Received new analyst entry information\n");
        analyst->service_type = *service_type;
        analyst->type = ANALYST;
        analyst->client_id = (*client_id)++;
        analyst->a_ssl = conn->ssl;
        
        
        printf("Adding entry of type %c\n", analyst->service_type);
        add_entry(analyst_list, analyst);
        send_msg(conn->ssl, NULL, 0, SUCCESS_RECEIPT);
    }
    if(msg_type == NEW_COLLECTOR || msg_type == COLLECTOR_CHECK) {
        printf("Received new collector entry information\n");
        INFO *analyst = check_match(analyst_list, *service_type);
        if(analyst == NULL) {
            // Write to say we received connection
            send_msg(conn->ssl, NULL, 0, SUCCESS_RECEIPT);
            printf("No analysts found for service\n");
            char receipt = NO_ANALYST_FOUND;
            // SSL write to collector to inform of failure
            send_msg(conn->ssl, &receipt, 1, SUCCESS_RECEIPT);
            SSL_shutdown(conn->ssl);
            SSL_free(conn->ssl);
            free(conn->ctx);
            free(conn);
            return -1;
        }
        if(msg_type == COLLECTOR_CHECK) {
            // Send success receipt of connection
            send_msg(conn->ssl, NULL, 0, SUCCESS_RECEIPT);
            // Send receipt of analyst found
            char receipt = ANALYST_FOUND;
            send_msg(conn->ssl, &receipt, sizeof(char), SUCCESS_RECEIPT);
            printf("Found analyst for service\n");
            return 0;
        }
        // Remove analyst from list
        remove_entry(analyst_list, analyst->client_id);
        
        // Add collector to list
        INFO *collector = malloc(sizeof(INFO));
        collector->service_type = *service_type;
        collector->type = COLLECTOR;
        collector->client_id = *client_id++;
        collector->c_ssl = conn->ssl;
        collector->a_ssl = analyst->a_ssl;
        
        
        add_entry(collector_list, collector);
        
        // Send success receipt of connection
        send_msg(conn->ssl, NULL, 0, SUCCESS_RECEIPT);
        // Send receipt of analyst found
        char receipt = ANALYST_FOUND;
        send_msg(conn->ssl, &receipt, sizeof(char), SUCCESS_RECEIPT);
        // Send message to analyst to say we have successfully connected
        receipt = COLLECTOR_FOUND;
        send_msg(analyst->a_ssl, &receipt, sizeof(char), SUCCESS_RECEIPT);
        printf("Found analyst for service\n");
    }
    return 0;
}

int service_collectors(node_t *collector_list)
{
    // Keep copy of original list
    node_t *collector_list_orig = collector_list;
    // Get a collector from list and move the list along one position
    INFO *collector = get_next_entry(&collector_list);
    // Keep going as long as we have a collector to service
    while(collector != NULL) {
        int msg_size = 0;
        char msg_type = 0;
        bool error = false;
        char *buf = NULL;
        // Recv from SSL connection to analyst
        buf = recv_msg(collector->a_ssl, &msg_size, &msg_type, &error);
        if(error == true) {
            fprintf(stderr, "Lost connection to analyst\n");
            msg_type = CLOSED_CON;
        }
        if(error_handler(msg_type) != 0) {
            send_msg(collector->c_ssl, NULL, 0, msg_type);
            remove_entry(collector_list_orig, collector->client_id);
            break;
        }
        
        // Send over SSL connection to collector
        int status;
        if((status = send_msg(collector->c_ssl, buf, msg_size, msg_type)) != 0) {
            // Error sending over ssl, inform analyst and remove collector from list
            free(buf);
            send_msg(collector->a_ssl, NULL, 0, status);
            remove_entry(collector_list_orig, collector->client_id);
            break;
        }
        free(buf);
        
        // Recv from SSL connection to collector
        buf = recv_msg(collector->c_ssl, &msg_size, &msg_type, &error);
        if(error == true) {
            fprintf(stderr, "Lost connection to collector\n");
            msg_type = CLOSED_CON;
        }
        if(error_handler(msg_type) != 0) {
            send_msg(collector->a_ssl, NULL, 0, msg_type);
            remove_entry(collector_list_orig, collector->client_id);
            break;
        }
        // printf("Size is %i\n", msg_size);
        // Send over SSL connection to analyst
        if((status = send_msg(collector->a_ssl, buf, msg_size, msg_type)) != 0) {
            free(buf);
            send_msg(collector->c_ssl, NULL, 0, status);
            remove_entry(collector_list_orig, collector->client_id);
        }
        free(buf);
        collector = get_next_entry(&collector_list);
    }
    return 0;
}

char *recv_msg(void *ssl, int *size, char *type, bool *error)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    char *header = malloc(header_size);
    // Receive message header
    if(SSL_read(ssl, header, header_size) <= 0) {
        *error = true;
        perror("SSL read");
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
    // Handle error messages
    if(error_handler(msg_type) != 0) {
        return NULL;
    }
    // If size is zero then no data to receive
    if(*size == 0) {
        return NULL;
    }
    char *buf = malloc(*size);
    // Receive data
    if(SSL_read(ssl, buf, *size) <= 0) {
        *error = true;
        perror("SSL read");
        free(header);
        free(buf);
        return NULL;
    }
    //free(header);
    return buf;
}

int send_msg(void *ssl, char *buf, int size, char type)
{
    int header_size = sizeof(uint32_t) + sizeof(char);
    // Create header for message
    char *header = malloc(header_size);
    // Make sure integer is in network byte order
    uint32_t network_size = htonl(size);
    memcpy(header, &network_size, sizeof(uint32_t));
    memcpy(header + sizeof(uint32_t), &type, sizeof(char));
    // Send message header
    if(SSL_write(ssl, header, header_size) <= 0) {
        perror("SSL write");
        free(header);
        return CLOSED_CON;
    }
    // If size is zero then no data to send
    if(size == 0) {
        return 0;
    }
    // Send data
    if(SSL_write(ssl, buf, size) <= 0) {
        perror("SSL write");
        free(header);
        return CLOSED_CON;
    }
    free(header);
    return 0;
}

int error_handler(char msg_type)
{
    switch(msg_type){
        case ERROR_RECEIPT  :
            return -1;
        case CLOSED_CON  :
            return -1;
        case SUCCESS_CLOSE  :
            return 1;
    }
    return 0;
}
