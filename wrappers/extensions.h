#include "../tls13_types.h"
#ifndef TLS_13_EXTENSIONS
#define TLS_13_EXTENSIONS

    ExtensionArray parse_extensions(unsigned char* data, int data_length);
    void free_extensions(ExtensionArray ea);
    void log_extensions(ExtensionArray ea, int indent_level);
    char* get_extension_name(uint16_t type);

#endif