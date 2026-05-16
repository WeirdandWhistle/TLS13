#include "../tls13_types.h"
#ifndef  TLS_13_RECORD
#define  TLS_13_RECORD

    TLSPlaintext read_record(int socket);
    void free_record(TLSPlaintext record);
    Array process_record(TLSPlaintext record);
    Array encrypt_record(TLSPlaintext record, unsigned char* key, unsigned char* nonce);
    TLSPlaintext decrypt_record(int socket, unsigned char* key, unsigned char* nonce);
    void process_record_headers(unsigned char* out, TLSPlaintext record);
    char* get_record_name(uint16_t type);
    void log_record_simple(TLSPlaintext record, int indent_level);

#endif