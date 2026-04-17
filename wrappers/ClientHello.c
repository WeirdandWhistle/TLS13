#include "../main.h"

ClientHello parse_client_hello(unsigned char* data, int data_length){
    ClientHello ch = {0};

    unsigned char* iter = data;

    memcpy(iter, ch.legacy_version, 2);
    iter += 2;

    memcpy(iter, ch.random, 32);
    iter += 32;

    memcpy(iter, &ch.legacy_session_id_length, 1);
    iter += 1;

    memcpy(iter, ch.legacy_session_id, ch.legacy_session_id_length);
    iter += ch.legacy_session_id_length;

    memcmp(iter, &ch.cipher_suites_length, 2);
    iter += 2;
    ch.cipher_suites_length = ntohs(ch.cipher_suites_length);

    memcpy(iter, ch.cipher_suites, ch.cipher_suites_length);
    iter += ch.cipher_suites_length;

    memcpy(iter, &ch.legacy_compression_methods_length, 1);
    iter += 1;
    ch.legacy_compression_methods_length = ntohs(ch.legacy_compression_methods_length);

    memcpy(iter, ch.legacy_compression_methods, ch.legacy_compression_methods_length);
    iter += ch.legacy_compression_methods_length;

    memcpy(iter, &ch.extensions_length, 2);
    iter += 2;
    ch.extensions_length = ntohs(ch.extensions_length);

    // extension parsing
}
