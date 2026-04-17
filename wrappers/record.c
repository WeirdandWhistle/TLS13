#include "../main.h"

TLSPlaintext read_record(int socket){
    TLSPlaintext record = {0};
    int rc = read(socket, &record.type, 1);
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