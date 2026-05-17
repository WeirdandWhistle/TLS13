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
    free(record.legacy_record_version);
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
int decrypt_record(TLSPlaintext* out, TLSPlaintext record, unsigned char* key, unsigned char* nonce){
    unsigned char additional_data[5];
    process_record_headers(additional_data, record);

    unsigned char* buf = malloc(record.length - AEAD_TAG_LENGTH + 100);
    unsigned long long buf_len = 0;
    if(buf==NULL)
        return -1;

    int rc = crypto_aead_chacha20poly1305_ietf_decrypt(buf, &buf_len,
                                            NULL,
                                            record.fragment, record.length,
                                            additional_data, sizeof(additional_data),
                                            nonce, key);

    if(rc!=0)
        return -2;
    if((int) buf_len!=record.length-AEAD_TAG_LENGTH)
        return -3;

    int padding_offset = 0;
    unsigned char* iter = buf;
    iter += buf_len - 1;
    while(*iter == 0){
        padding_offset++;
        iter--;
    }

    unsigned char content_type = buf[buf_len - 1 - padding_offset];
    // printf("padding offset: %d\n", padding_offset);
    // printf("content_type: %02x\n",content_type);
    // printf("content: "); print_hex(buf, buf_len - 1 - padding_offset);

    // TLSPlaintext out = {0};
    out->type = content_type;
    out->legacy_record_version = malloc(2);
    if(out->legacy_record_version==NULL)
        return -4;
    out->legacy_record_version[0] = record.legacy_record_version[0];
    out->legacy_record_version[1] = record.legacy_record_version[1];
    
    int out_len = buf_len - 1 - padding_offset;
    unsigned char* buf2 = malloc(out_len);
    if(out==NULL)
        return -5;

    memcpy(out, buf, out_len);
    
    free(buf);

    out->length = out_len;
    out->fragment = buf2;

    return 0;
}
void process_record_headers(unsigned char* out, TLSPlaintext record){
    out[0] = record.type;
    out[1] = record.legacy_record_version[0];
    out[2] = record.legacy_record_version[1];

    write_uint16(out+3, record.length);
    printf("record headers: "); print_hex(out, 5);
}
char* get_record_name(uint16_t type){
    switch (type)
    {
    case 0:
        return "invalid";
    case CHANGE_CIPHER_SPEC_TYPE:
        return "change_cipher_spec";
    case ALERT_TYPE:
        return "alert";
    case HANDSHAKE_TYPE:
        return "handshake";
    case APPLIACTION_TYPE:
        return "application_data";    
    default:
        return "unknown";
    }
}
void log_record_simple(TLSPlaintext record, int indent_level){
    indent(indent_level); printf("Length %d\n", record.length);
    indent(indent_level); printf("Type %s(%d)\n", get_record_name(record.type), record.type);
    indent(indent_level); printf("Version 0x%02x%02x\n", record.legacy_record_version[0], record.legacy_record_version[1]);
}