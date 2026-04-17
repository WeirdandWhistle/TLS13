#include "../tls13_types.h"
#ifndef TLS_CLIENT_HELLO_FILE
#define TLS_CLIENT_HELLO_FILE

    ClientHello parse_client_hello(unsigned char* data, int data_length);

#endif