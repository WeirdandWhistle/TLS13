#ifndef TLS_13_KEY_SCHEDULE
#define TLS_13_KEY_SCHEDULE

    void HKDF_Expand_Label(unsigned char* out, char* Secret, unsigned char* Label, int Label_length, unsigned char* Context, uint8_t Context_length);
    void process_server_handshake_traffic_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* transcipt_hash);
    void process_base_derived_secret(unsigned char* out);
    void process_handshake_secret(unsigned char* out, unsigned char* shared_secret, unsigned char* derived_secret);

#endif