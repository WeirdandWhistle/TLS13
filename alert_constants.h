#ifndef TLS_13_ALERT_CONSTANTS
#define TLS_13_ALERT_CONSTANTS

    #define WARNING_ALERT 1
    #define FATAL_ALERT 2

    #define CLOSE_NOTIFY_ALERT 0
    #define UNEXPECTED_MESSAGE_ALERT 10
    #define BAD_RECORD_MAC_ALERT 20
    #define RECORD_OVERFLOW_ALERT 22
    #define HANDSHAKE_FAILURE_ALERT 40
    #define BAD_CERTIFICATE_ALERT 42
    #define UNSUPPORTED_CERTIFICATE_ALERT 43
    #define CERTIFICATE_REVOKED_ALERT 44
    #define CERTIFICATE_EXPIRED_ALERT 45
    #define CERTIFICATE_UNKNOWN_ALERT 46
    #define ILLEGAL_PARAMETER_ALERT 47
    #define UNKNOWN_CA_ALERT 48
    #define ACCESS_DENIED_ALERT 49
    #define DECODE_ERROR_ALERT 50
    #define DECRYPT_ERROR_ALERT 51
    #define PROTOCOL_VERSION_ALERT 70
    #define INSUFFICIENT_SECURITY_ALERT 71
    #define INTERNAL_ERROR_ALERT 80
    #define INAPPROPRIATE_FALLBACK_ALERT 86
    #define USER_CANCELED_ALERT 90
    #define MISSING_EXTENSION_ALERT 109
    #define UNSUPPORTED_EXTENSION_ALERT 110
    #define UNRECOGNIZED_NAME_ALERT 112
    #define BAD_CERTIFICATE_STATUS_RESPONSE_ALERT 113
    #define UNKNOWN_PSK_IDENTITY_ALERT 115
    #define CERTIFICATE_REQUIRED_ALERT 116
    #define NO_APPLICATION_PROTOCOL_ALERT 120

    char* get_alert_name(int type){
        switch(type){
            case 0:
                    return "close_notify";
            case 10:
                    return "unexpected_message";
            case 20:
                    return "bad_record_mac";
            case 22:
                    return "record_overflow";
            case 40:
                    return "handshake_failure";
            case 42:
                    return "bad_certificate";
            case 43:
                    return "unsupported_certificate";
            case 44:
                    return "certificate_revoked";
            case 45:
                    return "certificate_expired";
            case 46:
                    return "certificate_unknown";
            case 47:
                    return "illegal_parameter";
            case 48:
                    return "unknown_ca";
            case 49:
                    return "access_denied";
            case 50:
                    return "decode_error";
            case 51:
                    return "decrypt_error";
            case 70:
                    return "protocol_version";
            case 71:
                    return "insufficient_security";
            case 80:
                    return "internal_error";
            case 86:
                    return "inappropriate_fallback";
            case 90:
                    return "user_canceled";
            case 109:
                    return "missing_extension";
            case 110:
                    return "unsupported_extension";
            case 112:
                    return "unrecognized_name";
            case 113:
                    return "bad_certificate_status_response";
            case 115:
                    return "unknown_psk_identity";
            case 116:
                    return "certificate_required";
            case 120:
                    return "no_application_protocol";
            default:
                    return "unknown";
        }
    }

#endif