#include "bank.h"

COIN b_coins[COINS_AVAIL];
int coin_count = 0;
int auth_count = 0;


int main(int argc, char *argv[])
{
    
    /* MANAGE ARGUMENTS && DETERMINE PORT TO BE USED */
    
    // initialise port to default specified in bank.h
    char *port = DEFAULT_PORT;
    
    
    //maybe have an argument for timeout aswell?
    
    // if argument specified for port number, amend port to specified
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            case 'p':
                if(optarg != NULL) {
                    port = optarg;
                } else {
                    fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
        }
    }
    
    
    //print port number being used
    fprintf(stderr, "port number: %s\n", port);
    
    //initialise bank here
    
    
    /* LET'S GET A SOCKET FOR COMMUNICATION */

    int listening_socket;
    if( (listening_socket = init_comm_on_port(port) ) < 0 ) {
        return 0; //e.g. check for errors
    }
    
    
    /* LET'S SET UP A SSL CONNECTION USING THIS SOCKET */
    
    // initialise OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    
    SSL_CONN *conn = establish_ssl_conn();
    
    //use this connection to serve clients
    if( serve_client(listening_socket, conn)  == -1) {
        fprintf(stderr, "serveclient in main");
        exit(EXIT_FAILURE);
    }
    
    /* CLOSE DOWN RESOURCES */
    close(listening_socket);
    
    /* FIN' */
    
    
    exit(EXIT_SUCCESS);
    return 0;
}


