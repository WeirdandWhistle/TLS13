#include "../tls13_types.h"
#ifndef TLS_13_ENCRYPTED_EXTENSIONS
#define TLS_13_ENCRYPTED_EXTENSIONS

    Array process_encrypted_extensions(EncryptedExtensions ee);
    void free_encrypted_extensions(EncryptedExtensions ee);

#endif