#ifndef TLS_13_UTIL_FILE
#define TLS_13_UTIL_FILE

    void print_hex(unsigned char *a, int aSize);
    uint32_t get_uint24(unsigned char* data);
    unsigned char* process_uint24(uint32_t num);
    void indent(int amount);

#endif
