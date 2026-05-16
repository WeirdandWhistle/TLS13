#ifndef CONSTANTS
#define CONSTANTS

    #define SEND_DUMB_MESSAGE 1
    #define DUMB_MESSAGE "Custom TLS1.3 STACK!!!\n"
    #define SOCKET_PORT 3000
    #define SOCKET_BACKLOG 5
    #define INDENT_PRODUCT 4
    #define INDENT_CHAR ' '
    #define PADDING_MIN 0 
    #define PADDING_MAX 0
    #define SEND_CERTIFICATE 1
    #define SEND_CHANGE_CIPHER_SPEC 1
    #define KEY_FILE "keys/ec_key.hex"
    #define CERT_FILE "keys/cert.der"

    #define SECRET_LENGTH 32
    #define HASH_LENGTH 32 // little late to be added but what ever
    #define AEAD_TAG_LENGTH 16
    #define NONCE_LENGTH 12

    #define SEND_FINISHED 1
    #define TLS_CHACHA20_POLY1305_SHA256 {0x13, 0x03}
    #define TLS_CHACHA20_POLY1305_SHA256_NUM 0x1303
    #define KEY_SHARE_EXTENSION_TYPE 51
    #define SUPPORTED_VERSIONS_EXTENSION_TYPE 43
    #define NAMED_GROUP_X25519 0x001D
    #define HANDSHAKE_TYPE 22
    #define APPLIACTION_TYPE 23
    #define ALERT_TYPE 21
    #define CHANGE_CIPHER_SPEC_TYPE 20
    #define CLIENT_HELLO_TYPE 1
    #define SERVER_HELLO_TYPE 2
    #define ENCRYPTED_EXTENSIONS 8
    #define CERTIFICATE_TYPE 11
    #define CERTIFICATE_VERIFY_TYPE 15
    #define FINISHED_TYPE 20
    #define ECDSA_SECP256R1_SHA256 0x0403
    #define CERT_VERIFY_CONTEXT_STRING "TLS 1.3, server CertificateVerify"

#endif