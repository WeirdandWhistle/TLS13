#ifndef TLS_13_CERTIFICATE
#define TLS_13_CERTIFICATE
#include "../tls13_types.h"

    Certificate create_certificate(char* file);
    Array process_certificate(Certificate c);
    void free_certificate(Certificate c);
    int certificate_chain_length(CertificateChain cc);
    Array process_certificate_entry(CertificateEntry ce);

#endif