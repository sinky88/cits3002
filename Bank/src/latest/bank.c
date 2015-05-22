#include "bank.h"

FILE* output_stream;
FILE* coinlist;
COIN b_coins[COINS_AVAIL];
int coin_count = 0;


int main(int argc, char *argv[])
{
    
    //initialise bank here
    output_stream = DEFAULT_OUT_STREAM;
    
    coinlist = fopen(COINS_LIST, "w+");
    
    fclose(coinlist);
    // initialise port to default specified in bank.h
    char *port = DEFAULT_PORT;
    
    
    /* ARGUMENTS */
    
    int opt = 0;
    char *optString = OPT_STRING;
    while((opt = getopt(argc, argv, optString)) != -1)
    {
        switch(opt)
        {
            case 'p':
            {
                if(optarg != NULL) {
                    port = optarg;
                } else {
                    fprintf(output_stream, "Usage: %s [-p port]\n", argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            }
            
        }
    }
    
    //print port number being used
    fprintf(output_stream, "using port %s...\n", port);
    
    /* GET A SOCKET TO LISTEN FOR INCOMING CONNECTIONS w/ PORT */
    int listening_socket; // listens for any incoming communication for port
    if( (listening_socket = init_comm_on_port(port) ) < 0 ) {
        fprintf(output_stream, "unable to get listening port\nTERMINATE");
        exit(EXIT_FAILURE);
        return -1;
    }
    
    /* INITIALISE SSL AND HOLD USEFUL VARIABLES IN SSL_INFO STRUCTURE */
    SSL_INFO *conn = establish_ssl_conn();
    if (conn == NULL) {
        fprintf(output_stream, "unable to load SSL\nTERMINATE");
        exit(EXIT_FAILURE);
        return -1;
    }
    
    /* SERVE CLIENTS AS THEY CONNECT USING TCP/SSL */
    if( serve_client(listening_socket, conn)  == -1) {
        fprintf(output_stream, "serveclient in main");
        exit(EXIT_FAILURE);
        return -1;
    }
    
    /* CLOSE DOWN RESOURCES */
    close(listening_socket);
    
    /* FIN' */
    
    
    exit(EXIT_SUCCESS);
    return 0;
}


