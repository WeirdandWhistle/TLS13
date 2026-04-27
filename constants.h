#ifndef CONSTANTS
#define CONSTANTS

    #define SOCKET_PORT 3000
    #define SOCKET_BACKLOG 5
    #define INDENT_PRODUCT 4
    #define INDENT_CHAR ' '
    #define PADDING_MIN 0 
    #define PADDING_MAX 100
    #define SEND_CERTIFICATE 1
    #define KEY_FILE "keys/ec_key.hex"
    #define CERT_FILE "keys/cert.der"

    #define SECRET_LENGTH 32
    #define AEAD_TAG_LENGTH 16
    #define NONCE_LENGTH 12

    #define TLS_CHACHA20_POLY1305_SHA256 {0x13, 0x03}
    #define KEY_SHARE_EXTENSION_TYPE 51
    #define SUPPORTED_VERSIONS_EXTENSION_TYPE 43
    #define NAMED_GROUP_X25519 0x001D
    #define SERVER_HELLO_HEADER 2
    #define HANDSHAKE_TYPE 22

#endif