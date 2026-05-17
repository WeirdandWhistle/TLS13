#ifndef TLS_13_STATE_MACHINE
#define TLS_13_STATE_MACHINE
#include <sodium.h>

    enum TLS_STATE {
        UNENCRYPTED, ENCRYPTED
    };

    typedef struct {
        enum TLS_STATE state;
        int socket;
        uint16_t cipher_suite;
        unsigned char* shared_secret;
        unsigned char* handshake_secret;
        unsigned char* master_secret;
        crypto_hash_sha256_state hash_state;
        unsigned char* server_handshake_traffic_secret;
        unsigned char* client_handshake_traffic_secret;
        unsigned char* server_application_traffic_secret;
        unsigned char* client_application_traffic_secret;
        unsigned char* server_write_key;
        unsigned char* client_write_key;
        unsigned char* server_write_iv;
        unsigned char* client_write_iv;
        unsigned long long server_nonce_counter;
        unsigned long long client_nonce_counter;
    } TLS_SERVER_STATE;

    void free_TLS_SERVER_STATE(TLS_SERVER_STATE* s);
    int main_state_mech(TLS_SERVER_STATE* state, TLSPlaintext record, int logging);
    int ClientHello_ServerHello_handshake(TLS_SERVER_STATE* state, ClientHello client_hello, int logging, int indent_level);
    int send_null_EncryptedExtensions(TLS_SERVER_STATE* state, int logging, int indent_level);
    int init_TLS_SERVER_STATE(TLS_SERVER_STATE* s);

#endif