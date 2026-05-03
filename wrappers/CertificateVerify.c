#include "../main.h"
#include "../micro_ecc/uECC.h"
Array process_signature_content(unsigned char* transcipt_hash){
    int len = 64 + (sizeof(CERT_VERIFY_CONTEXT_STRING)-1) + 1 + SECRET_LENGTH;
    unsigned char* buf = malloc(len);
    assert(buf!=NULL);

    unsigned char* iter = buf;

    for(int i = 0; i<64;i++){
        *iter = 0x20;
        iter++;
    }

    memcpy(iter, CERT_VERIFY_CONTEXT_STRING, sizeof(CERT_VERIFY_CONTEXT_STRING)-1);
    iter += sizeof(CERT_VERIFY_CONTEXT_STRING)-1;

    *iter = 0;
    iter++;

    memcpy(iter, transcipt_hash, SECRET_LENGTH);

    Array arr = {0};
    arr.ptr = buf;
    arr.length = len;
    return arr;
}
void load_cert_private_key(unsigned char* out, char* file_string){
    unsigned char hex_key[SECRET_LENGTH * 2];

    FILE* file = fopen(file_string, "r");
    fread(hex_key, 1, SECRET_LENGTH *2, file);
    fclose(file);

    size_t hex_out_len;

    sodium_hex2bin(out, SECRET_LENGTH,
                    (char*)hex_key, sizeof(hex_key),
                    NULL, &hex_out_len,
                    NULL);

    assert(hex_out_len==SECRET_LENGTH);
}
CertificateVerify create_certificate_verify(unsigned char* transcipt_hash){
    unsigned char cert_private_key[32];
    load_cert_private_key(cert_private_key, KEY_FILE);

    Array to_sign_arr = process_signature_content(transcipt_hash);

    uECC_Curve curve = uECC_secp256r1();

    free(to_sign_arr.ptr);
}