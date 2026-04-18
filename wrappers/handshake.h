#include "../tls13_types.h"
#ifndef TLS_13_HANDSHAKE
#define TLS_13_HANDSHAKE

    Handshake parse_handshake(unsigned char* data, int data_length);
    void free_handshake(Handshake handshake);
    Array process_handshake(Handshake handshake);

#endif