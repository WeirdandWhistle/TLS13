#include "../main.h"

TLSPlaintext read_record(int socket){
    TLSPlaintext record = {0};
    int rc = read(socket, &record.type, 1);
    assert(rc==1);
    record.legacy_record_version = malloc(2);
    assert(record.legacy_record_version!=NULL);
    rc = read(socket, record.legacy_record_version, 2);
    // printf("2. rc=%d; errno:%s\n",rc,strerror(errno));
    assert(rc==2);
    rc = read(socket, &record.length, 2);
    assert(rc==2);
    record.length = ntohs(record.length);

    unsigned char* buf = malloc(record.length);
    assert(buf!=NULL);

    rc = read(socket, buf, record.length);
    if(rc!=record.length){
        printf("buffer over/under-flow. aborting record read.\n");
        assert(0);
    }

    record.fragment = buf;
    return record;
}
void free_record(TLSPlaintext record){
    free(record.fragment);
}
Array process_record(TLSPlaintext record){
    int length = 1 + 2 + 2 + record.length;
    unsigned char* buf = malloc(length);
    unsigned char* iter = buf;

    *iter = record.type;
    iter++;

    memcpy(iter, record.legacy_record_version, 2);
    iter += 2;

    write_uint16(iter, record.length);
    iter += 2;

    memcpy(iter, (unsigned char*)record.fragment, record.length);

    Array arr = {0};
    arr.length = length;
    arr.ptr = buf;

    return arr;
}
/* DONT foret ti free the ptr*/
Array encrypt_record(TLSPlaintext record, unsigned char* key, unsigned char* nonce){
    int padding_length = rand() % (PADDING_MAX - PADDING_MIN + 1) + PADDING_MIN;
    printf("padding_length: %d\n",padding_length);
    uint16_t TLSInnerPlainText_length = (record.length + 1 + padding_length);
    int len = 1 + 2 + 2 + TLSInnerPlainText_length + AEAD_TAG_LENGTH;

    unsigned char* TLSInnerPlainText = malloc(TLSInnerPlainText_length);
    assert(TLSInnerPlainText!=NULL);

    unsigned char cipher_text_headers[1+2+2];
    
    unsigned char* iter = cipher_text_headers;
    *iter = 23; // appliaction
    iter++;

    *iter = 0x03;
    iter++;
    *iter = 0x03;
    iter++;

    uint16_t uint16_buf = len - sizeof(cipher_text_headers);
    uint16_buf = htons(uint16_buf);
    memcpy(iter, &uint16_buf, 2);

    iter = TLSInnerPlainText;

    memcpy(iter, record.fragment, record.length);
    iter += record.length;

    *iter = record.type;
    iter++;

    for(int i = 0; i<padding_length;i++){
        *iter = 0;
        iter++;
    }

    unsigned char* cipher_text = malloc(TLSInnerPlainText_length + AEAD_TAG_LENGTH);
    unsigned long long cipher_text_length;

    unsigned long long TLSIPLTL_buf = TLSInnerPlainText_length;

    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(cipher_text, &cipher_text_length,
                                                        TLSInnerPlainText, TLSIPLTL_buf,
                                                        cipher_text_headers, sizeof(cipher_text_headers),
                                                        NULL,
                                                        nonce, key);
    
    assert(cipher_text_length == len - sizeof(cipher_text_headers));      
    
    printf("RC: %d\nciphertext_length: %d\nlen: %d\n",rc,cipher_text_length,len);

    unsigned char* buf = malloc(sizeof(cipher_text_headers) + cipher_text_length);
    assert(buf!=NULL);
    iter = buf;

    memcpy(iter, cipher_text_headers, sizeof(cipher_text_headers));
    iter += sizeof(cipher_text_headers);

    memcpy(iter, cipher_text, cipher_text_length);

    free(TLSInnerPlainText);
    free(cipher_text);

    Array arr = {0};
    arr.ptr = buf;
    arr.length = len;
    return arr;
}