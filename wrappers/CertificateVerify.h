#ifndef TLS_13_CERT_VERIFY
#define TLS_13_CERT_VERIFY
#include "../tls13_types.h"

    Array process_signature_content(unsigned char* transcipt_hash);
    void load_cert_private_key(unsigned char* out, char* file);
    CertificateVerify create_certificate_verify(unsigned char* transcipt_hash);
    void free_certificate_verify(CertificateVerify cv);
    Array process_certificate_verify(CertificateVerify cv);
#endif