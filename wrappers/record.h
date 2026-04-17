#include "../tls13_types.h"
#ifndef  TLS_13_RECORD
#define  TLS_13_RECORD

TLSPlaintext read_record(int socket);
void free_record(TLSPlaintext record);

#endif