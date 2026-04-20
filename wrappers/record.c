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

    memcpy(iter, &record.length, 2);
    iter += 2;

    memcpy(iter, (unsigned char*)record.fragment, record.length);

    Array arr = {0};
    arr.length = length;
    arr.ptr = buf;

    return arr;
}