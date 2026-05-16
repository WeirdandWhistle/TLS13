#include "../main.h"
void process_full_alert_simple(unsigned char* out, Alert a){
    out[0] = ALERT_TYPE;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = 0;
    out[4] = 2;
    out[5] = a.level;
    out[6] = a.description;
}