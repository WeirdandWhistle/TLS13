#include "../tls13_types.h"
#ifndef TLS_13_SERVER_HELLO
#define TLS_13_SERVER_HELLO

    Array process_server_hello(ServerHello sh);
    ServerHello create_server_hello(
        unsigned char random[32],
        uint8_t legacy_session_id_echo_length,
        unsigned char* legacy_session_id_echo,
        unsigned char cipher_suite[2],
        uint16_t extensions_length,
        ExtensionArray ea
    );
    void free_server_hello(ServerHello sh);

#endif