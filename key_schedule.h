#ifndef TLS_13_KEY_SCHEDULE
#define TLS_13_KEY_SCHEDULE

    void HKDF_Expand_Label(unsigned char* out, char* Secret, unsigned char* Label, int Label_length, unsigned char* Context, uint8_t Context_length, uint16_t length);
    void process_server_handshake_traffic_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* transcipt_hash);
    void process_base_derived_secret(unsigned char* out);
    void process_handshake_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* derived_secret);
    void generate_nonce(unsigned char *out, unsigned char *iv, uint8_t counter);
    void generate_write_key(unsigned char* out, unsigned char* secret);
    void generate_write_iv(unsigned char* out, unsigned char* secret);

#endif