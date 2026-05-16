#ifndef TLS_13_ALERT
#define TLS_13_ALERT
#include "../constants.h"
#include "../tls13_types.h"

    #define FULL_ALERT_LENGTH 7
    void process_full_alert_simple(unsigned char* out, Alert a);

#endif