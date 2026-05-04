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

    unsigned char* hash_buf = malloc(SECRET_LENGTH);
    assert(hash_buf!=NULL);

    crypto_hash_sha256(hash_buf, buf, len);

    free(buf);

    Array arr = {0};
    arr.ptr = hash_buf;
    arr.length = SECRET_LENGTH;
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

    unsigned char signature[2*SECRET_LENGTH];

    int rc = uECC_sign(cert_private_key, to_sign_arr.ptr, SECRET_LENGTH, signature, curve);
    printf("cert singing rc: %d\n", rc);

    free(to_sign_arr.ptr);

    unsigned char r[SECRET_LENGTH];
    memcpy(r, signature, SECRET_LENGTH);
    unsigned char s[SECRET_LENGTH];
    memcpy(s, signature+SECRET_LENGTH, SECRET_LENGTH);

    int r_pad = r[0] >= 0x80 ? 1 : 0;
    int s_pad = s[0] >= 0x80 ? 1 : 0;

    uint8_t r_len = sizeof(r) + r_pad;
    uint8_t s_len = sizeof(s) + s_pad;
    //                    ASN.1 DER start tag  full length  int tag  length tag  r len  int tag  length tag  s len
    uint8_t full_der_payload_len = 1                    + 1            + 1      + 1     + r_len   + 1       + 1     + s_len;
    uint8_t der_payload_length = full_der_payload_len - 2;
    
    const uint8_t INT_TYPE_ASN_DER = 0x02;

    unsigned char* buf = malloc(full_der_payload_len);
    assert(buf!=NULL);
    unsigned char* iter = buf;

    *iter = 0x30; //cosnt
    iter++;

    *iter = der_payload_length;
    iter++;

    *iter = INT_TYPE_ASN_DER;
    iter++;

    *iter = r_len;
    iter++;

    if(r_pad){
        *iter = 0x00;
        iter++;
    }

    memcpy(iter, r, sizeof(r));
    iter += sizeof(r);

    *iter = INT_TYPE_ASN_DER;
    iter++;

    *iter = s_len;
    iter++;

    if(s_pad){
        *iter = 0x00;
        iter++;
    }

    memcpy(iter, s, sizeof(s));
    

    CertificateVerify cv = {0};
    cv.signature_length = full_der_payload_len;
    cv.signature = buf;
    cv.algorithm = ECDSA_SECP256R1_SHA256;
    return cv;
}
void free_certificate_verify(CertificateVerify cv){
    free(cv.signature);
}
Array process_certificate_verify(CertificateVerify cv){
    int len = 2 + 2 + cv.signature_length;

    unsigned char* buf = malloc(len);
    assert(buf!=NULL);

    unsigned char* iter = buf;

    uint16_t uint16_buf = htons(cv.algorithm);
    memcpy(iter, &uint16_buf, 2);
    iter += 2;
    
    uint16_buf = htons(cv.signature_length);
    memcpy(iter, &uint16_buf, 2);
    iter += 2;

    memcpy(iter, cv.signature, cv.signature_length);

    Array arr = {0};
    arr.ptr = buf;
    arr.length = len;
    return arr;
}