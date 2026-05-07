#include "../main.h"
#include <time.h>

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
    srand(time(NULL));
    int padding_length = rand() % (PADDING_MAX - PADDING_MIN + 1) + PADDING_MIN;
    // printf("padding_length: %d\n",padding_length);
    uint16_t TLSInnerPlainText_length = (record.length + 1 + padding_length);
    int len = 1 + 2 + 2 + TLSInnerPlainText_length + AEAD_TAG_LENGTH;

    unsigned char* TLSInnerPlainText = malloc(TLSInnerPlainText_length);
    assert(TLSInnerPlainText!=NULL);

    unsigned char additonal_data[1+2+2];
    
    unsigned char* iter = additonal_data;
    *iter = 23; // appliaction
    iter++;

    *iter = 0x03;
    iter++;
    *iter = 0x03;
    iter++;

    uint16_t uint16_buf = len - sizeof(additonal_data);
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
    assert(cipher_text!=NULL);

    unsigned long long TLSIPLTL_buf = TLSInnerPlainText_length;

    // printf("ci");

    int rc = crypto_aead_chacha20poly1305_ietf_encrypt(cipher_text, &cipher_text_length,
                                                        TLSInnerPlainText, TLSIPLTL_buf,
                                                        additonal_data, sizeof(additonal_data),
                                                        NULL,
                                                        nonce, key);
                                                        
    assert(rc==0);
    assert(cipher_text_length == len - sizeof(additonal_data));
    assert(len == (int)(sizeof(additonal_data) + cipher_text_length));      

    unsigned char* buf = malloc(sizeof(additonal_data) + cipher_text_length);
    assert(buf!=NULL);
    iter = buf;

    memcpy(iter, additonal_data, sizeof(additonal_data));
    iter += sizeof(additonal_data);

    memcpy(iter, cipher_text, cipher_text_length);

    free(TLSInnerPlainText);
    free(cipher_text);

    Array arr = {0};
    arr.ptr = buf;
    arr.length = len;
    return arr;
}
TLSPlaintext decrypt_record(int socket, unsigned char* key, unsigned char* nonce){
    TLSPlaintext er = read_record(socket);

    if(er.type != APPLIACTION_TYPE){
        assert(0 && "record has to be appliction type");
    }
    if(er.legacy_record_version[0] != 0x03 || er.legacy_record_version[1] != 0x03){
        assert(0 && "record must be version TLS 1.2 (0x0303)");
    }
    assert(er.fragment!=NULL);

    unsigned char additional_data[5];
    process_record_headers(additional_data, er);

    unsigned char* buf = malloc(er.length - AEAD_TAG_LENGTH + 100);
    unsigned long long buf_len = 0;
    assert(buf!=NULL);

    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(buf, &buf_len,
                                            NULL,
                                            er.fragment, er.length,
                                            additional_data, sizeof(additional_data),
                                            nonce, key);

    assert(rc==0);
    assert((int) buf_len==er.length-AEAD_TAG_LENGTH);

    int padding_offset = 0;
    unsigned char* iter = buf + buf_len-1;
    while(*iter == 0){
        padding_offset++;
        iter--;
    }

    unsigned char content_type = buf[buf_len - 1 - padding_offset];
    printf("content_type: %02x\n",content_type);
    printf("content: "); print_hex(buf, buf_len - 1 - padding_offset);

    return er;
}
void process_record_headers(unsigned char* out, TLSPlaintext record){
    out[0] = record.type;
    out[1] = record.legacy_record_version[0];
    out[2] = record.legacy_record_version[1];

    write_uint16(out+3, record.length);
    printf("record headers: "); print_hex(out, 5);
}