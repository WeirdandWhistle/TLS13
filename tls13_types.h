#include <stdint.h>

#ifndef TLS_13_TYPES
#define TLS_13_TYPES
    /* copy past types for refrence from RFC8446
    enum {
          invalid(0),
          change_cipher_spec(20),
          alert(21),
          handshake(22),
          application_data(23),
          (255)
      } ContentType;

      enum {
          client_hello(1),
          server_hello(2),
          new_session_ticket(4),
          end_of_early_data(5),
          encrypted_extensions(8),
          certificate(11),
          certificate_request(13),
          certificate_verify(15),
          finished(20),
          key_update(24),
          message_hash(254),
          (255)
      } HandshakeType;
    */

    typedef struct {
          unsigned char type; //ContentType
          unsigned char legacy_record_version[2];
          uint16_t length;
          unsigned char* fragment;
    } TLSPlaintext;

    typedef struct {
        unsigned char msg_type;
        uint32_t length; //Uint24
        void* body;
    } Handshake;

    typedef struct {
        unsigned char level; //AlertLevel
        unsigned char description; //AlertDescription
    } Alert;

    /*
    enum { warning(1), fatal(2), (255) } AlertLevel;

      enum {
          close_notify(0),
          unexpected_message(10),
          bad_record_mac(20),
          record_overflow(22),
          handshake_failure(40),
          bad_certificate(42),
          unsupported_certificate(43),
          certificate_revoked(44),
          certificate_expired(45),
          certificate_unknown(46),
          illegal_parameter(47),
          unknown_ca(48),
          access_denied(49),
          decode_error(50),
          decrypt_error(51),
          protocol_version(70),
          insufficient_security(71),
          internal_error(80),
          inappropriate_fallback(86),
          user_canceled(90),
          missing_extension(109),
          unsupported_extension(110),
          unrecognized_name(112),
          bad_certificate_status_response(113),
          unknown_psk_identity(115),
          certificate_required(116),
          no_application_protocol(120),
          (255)
      } AlertDescription;
    */

#endif