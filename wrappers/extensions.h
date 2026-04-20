#include "../tls13_types.h"
#ifndef TLS_13_EXTENSIONS
#define TLS_13_EXTENSIONS

    ExtensionArray parse_extensions(unsigned char* data, int data_length);
    void free_extensions(ExtensionArray ea);
    Array process_extensions(ExtensionArray ea); 
    int extensions_length(ExtensionArray ea);
    void log_extensions(ExtensionArray ea, int indent_level);
    char* get_extension_name(uint16_t type);
    ExtensionArray grow_extensions(ExtensionArray ea, int amount);
    ExtensionArray add_key_share(ExtensionArray ea, uint16_t group, unsigned char* key_exchange, uint16_t key_exchange_length);

#endif