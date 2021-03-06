#include <string.h>
#include <stdlib.h>
#include <string.h>
#include "Usage.c"
#include <stdint.h>
#include "mbedtls/net.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#define mbedtls_fprintf fprintf
#define mbedtls_snprintf snprintf
#endif

namespace Constants{
  static const int REQUEST_SIZE = -1;
  static const int DEBUG_LEVEL = 0;
  static const int NBIO = 0;
  static const int READ_TIMEOUT = 0;
  static const int MAX_RESEND = 0;
  static const int FORCE_CIPHER =  0;
  static const int RENEGOTIATION = MBEDTLS_SSL_RENEGOTIATION_DISABLED;
  static const int ALLOW_LEGACY =  -2;
  static const int RENEGOTIATE =   0;
  static const int EXCHANGES =     1;
  static const int MIN_VERSION =   -1;
  static const int MAX_VERSION =   -1;
  static const int ARC4 =    -1;
  static const int AUTH_MODE =     -1;
  static const int MFL_CODE = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;
  static const int TRUNC_HMAC =    -1;
  static const int RECSPLIT =-1;
  static const int DHMLEN =  -1;
  static const int RECONNECT =     0;
  static const int RECO_DELAY =    0;
  static const int RECONNECT_HARD =0;
  static const int TICKETS = MBEDTLS_SSL_SESSION_TICKETS_ENABLED;
  static const int TRANSPORT =     MBEDTLS_SSL_TRANSPORT_STREAM;
  static const int HS_TO_MIN =     0;
  static const int HS_TO_MAX =     0;
  static const int FALLBACK =-1;
  static const int EXTENDED_MS =   -1;
  static const int ETM =     -1;
}

class Options
{
public:
    const char *server_name;    /* hostname of the server (client only)     */
    const char *server_addr;    /* address of the server (client only)      */
    const char *server_port;    /* port on which the ssl service runs       */
    int debug_level;            /* level of debugging                       */
    int nbio;                   /* should I/O be blocking?                  */
    uint32_t read_timeout;      /* timeout on mbedtls_ssl_read() in milliseconds    */
    int max_resend;             /* DTLS times to resend on read timeout     */
    const char *request_page;   /* page on server to request                */
    int request_size;           /* pad request with header to requested size */
    const char *ca_file;        /* the file with the CA certificate(s)      */
    const char *ca_path;        /* the path with the CA certificate(s) reside */
    const char *crt_file;       /* the file with the client certificate     */
    const char *key_file;       /* the file with the client key             */
    const char *psk;            /* the pre-shared key                       */
    const char *psk_identity;   /* the pre-shared key identity              */
    const char *ecjpake_pw;     /* the EC J-PAKE password                   */
    int force_ciphersuite[2];   /* protocol/ciphersuite to use, or all      */
    int renegotiation;          /* enable / disable renegotiation           */
    int allow_legacy;           /* allow legacy renegotiation               */
    int renegotiate;            /* attempt renegotiation?                   */
    int renego_delay;           /* delay before enforcing renegotiation     */
    int exchanges;              /* number of data exchanges                 */
    int min_version;            /* minimum protocol version accepted        */
    int max_version;            /* maximum protocol version accepted        */
    int arc4;                   /* flag for arc4 suites support             */
    int auth_mode;              /* verify mode for connection               */
    unsigned char mfl_code;     /* code for maximum fragment length         */
    int trunc_hmac;             /* negotiate truncated hmac or not          */
    int recsplit;               /* enable record splitting?                 */
    int dhmlen;                 /* minimum DHM params len in bits           */
    int reconnect;              /* attempt to resume session                */
    int reco_delay;             /* delay in seconds before resuming session */
    int reconnect_hard;         /* unexpectedly reconnect from the same port */
    int tickets;                /* enable / disable session tickets         */
    const char *alpn_string;    /* ALPN supported protocols                 */
    int transport;              /* TLS or DTLS?                             */
    uint32_t hs_to_min;         /* Initial value of DTLS handshake timer    */
    uint32_t hs_to_max;         /* Max value of DTLS handshake timer        */
    int fallback;               /* is this a fallback connection?           */
    int extended_ms;            /* negotiate extended master secret?        */
    int etm;                    /* negotiate encrypt then mac?              */

    Options();
    bool HandleCliArgs(int argc, char** argv);
    int HandleCiphersuiteRequest();
    bool IsCiphersuiteForced();
    bool IsPSKEnabled();
    void UnhexifyPSK(unsigned char *psk, size_t psk_len);
    void SslAlpn(const char** alpn_list);
};
