#include "../main.h"

TLSPlaintext read_record(int socket){
    TLSPlaintext record = {0};
    int rc = read(socket, &record.type, 1);
    printf("1. rc=%d\n",rc);
    assert(rc==1);
    rc = read(socket, record.legacy_record_version, 2);
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
Array process_record(TLSPlaintext record, Array body){
    int length = 1 + 2 + 2 + record.length;
    unsigned char* buf = malloc(length);
    unsigned char* iter = buf;

    *iter = record.type;
    iter++;

    memcpy(iter, record.legacy_record_version, 2);
    iter += 2;

    memcpy(iter, &record.length, 2);
    iter += 2;

    memcpy(iter, body.ptr, body.length);

    Array arr = {0};
    arr.length = length;
    arr.ptr = buf;

    return arr;
}