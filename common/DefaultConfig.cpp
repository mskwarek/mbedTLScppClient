#include "DefaultConfig.h"

static bool int_print_usage(int ret);

Options::Options()
{
  this->server_name         = "localhost";
    this->server_addr         = NULL;
    this->server_port         = "443";
    this->debug_level         = Constants::DEBUG_LEVEL;
    this->nbio                = Constants::NBIO;
    this->read_timeout        = Constants::READ_TIMEOUT;
    this->max_resend          = Constants::MAX_RESEND;
    this->request_page        = "/";
    this->request_size        = Constants::REQUEST_SIZE;
    this->ca_file             = "";
    this->ca_path             = "";
    this->crt_file            = "";
    this->key_file            = "";
    this->psk                 = "";
    this->psk_identity        = "Client_identity";
    this->ecjpake_pw          = NULL;
    this->force_ciphersuite[0]= Constants::FORCE_CIPHER;
    this->renegotiation       = Constants::RENEGOTIATION;	
    this->allow_legacy        = Constants::ALLOW_LEGACY;
    this->renegotiate         = Constants::RENEGOTIATE;
    this->exchanges           = Constants::EXCHANGES;
    this->min_version         = Constants::MIN_VERSION;
    this->max_version         = Constants::MAX_VERSION;
    this->arc4                = Constants::ARC4;
    this->auth_mode           = Constants::AUTH_MODE;
    this->mfl_code            = Constants::MFL_CODE;
    this->trunc_hmac          = Constants::TRUNC_HMAC;
    this->recsplit            = Constants::RECSPLIT;
    this->dhmlen              = Constants::DHMLEN;
    this->reconnect           = Constants::RECONNECT;
    this->reco_delay          = Constants::RECO_DELAY;
    this->reconnect_hard      = Constants::RECONNECT_HARD;
    this->tickets             = Constants::TICKETS;
    this->alpn_string         = NULL;
    this->transport           = Constants::TRANSPORT;
    this->hs_to_min           = Constants::HS_TO_MIN;
    this->hs_to_max           = Constants::HS_TO_MAX;
    this->fallback            = Constants::FALLBACK;
    this->extended_ms         = Constants::EXTENDED_MS;
    this->etm                 = Constants::ETM;
}

bool Options::HandleCliArgs(int argc, char** argv)
{
	int i = 0;
	char *p = NULL;
	char *q = NULL;
	int ret;
	for(int x = 0; x<argc;x++)
	  mbedtls_printf("%s", argv[x]);

    if( argc == 0 )
    {
    	int_print_usage(ret);
	throw 1;
    }

    for( i = 1; i < argc; i++ )
    {
        p = argv[i];
        mbedtls_printf("%s", p);
	if( ( q = strchr( p, '=' ) ) == NULL )
	  {
            int_print_usage(ret);
	    throw 1;
	  }
	*q++ = '\0';

        if( strcmp( p, "server_name" ) == 0 )
            this->server_name = q;
        else if( strcmp( p, "server_addr" ) == 0 )
            this->server_addr = q;
        else if( strcmp( p, "server_port" ) == 0 )
            this->server_port = q;
        else if( strcmp( p, "dtls" ) == 0 )
        {
            int t = atoi( q );
            if( t == 0 )
                this->transport = MBEDTLS_SSL_TRANSPORT_STREAM;
            else if( t == 1 )
                this->transport = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
            else
	      {
                int_print_usage(ret);
		throw 1;
	      }
        }
        else if( strcmp( p, "debug_level" ) == 0 )
        {
            this->debug_level = atoi( q );
            if( this->debug_level < 0 || this->debug_level > 65535 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "nbio" ) == 0 )
        {
            this->nbio = atoi( q );
            if( this->nbio < 0 || this->nbio > 2 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "read_timeout" ) == 0 )
            this->read_timeout = atoi( q );
        else if( strcmp( p, "max_resend" ) == 0 )
        {
            this->max_resend = atoi( q );
            if( this->max_resend < 0 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "request_page" ) == 0 )
            this->request_page = q;
        else if( strcmp( p, "request_size" ) == 0 )
        {
            this->request_size = atoi( q );
            if( this->request_size < 0 || this->request_size > MBEDTLS_SSL_MAX_CONTENT_LEN )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "ca_file" ) == 0 )
            this->ca_file = q;
        else if( strcmp( p, "ca_path" ) == 0 )
            this->ca_path = q;
        else if( strcmp( p, "crt_file" ) == 0 )
            this->crt_file = q;
        else if( strcmp( p, "key_file" ) == 0 )
            this->key_file = q;
        else if( strcmp( p, "psk" ) == 0 )
            this->psk = q;
        else if( strcmp( p, "psk_identity" ) == 0 )
            this->psk_identity = q;
        else if( strcmp( p, "ecjpake_pw" ) == 0 )
            this->ecjpake_pw = q;
        else if( strcmp( p, "force_ciphersuite" ) == 0 )
        {
            this->force_ciphersuite[0] = mbedtls_ssl_get_ciphersuite_id( q );

            if( this->force_ciphersuite[0] == 0 )
            {
                ret = 2;
                return int_print_usage(ret);
            }
            this->force_ciphersuite[1] = 0;
        }
        else if( strcmp( p, "renegotiation" ) == 0 )
        {
            this->renegotiation = (atoi( q )) ? MBEDTLS_SSL_RENEGOTIATION_ENABLED :
                                              MBEDTLS_SSL_RENEGOTIATION_DISABLED;
        }
        else if( strcmp( p, "allow_legacy" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case -1: this->allow_legacy = MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE; break;
                case 0:  this->allow_legacy = MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION; break;
                case 1:  this->allow_legacy = MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION; break;
                default: return int_print_usage(ret);
            }
        }
        else if( strcmp( p, "renegotiate" ) == 0 )
        {
            this->renegotiate = atoi( q );
            if( this->renegotiate < 0 || this->renegotiate > 1 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "exchanges" ) == 0 )
        {
            this->exchanges = atoi( q );
            if( this->exchanges < 1 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "reconnect" ) == 0 )
        {
            this->reconnect = atoi( q );
            if( this->reconnect < 0 || this->reconnect > 2 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "reco_delay" ) == 0 )
        {
            this->reco_delay = atoi( q );
            if( this->reco_delay < 0 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "reconnect_hard" ) == 0 )
        {
            this->reconnect_hard = atoi( q );
            if( this->reconnect_hard < 0 || this->reconnect_hard > 1 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "tickets" ) == 0 )
        {
            this->tickets = atoi( q );
            if( this->tickets < 0 || this->tickets > 2 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "alpn" ) == 0 )
        {
            this->alpn_string = q;
        }
        else if( strcmp( p, "fallback" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: this->fallback = MBEDTLS_SSL_IS_NOT_FALLBACK; break;
                case 1: this->fallback = MBEDTLS_SSL_IS_FALLBACK; break;
                default: return int_print_usage(ret);
            }
        }
        else if( strcmp( p, "extended_ms" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: this->extended_ms = MBEDTLS_SSL_EXTENDED_MS_DISABLED; break;
                case 1: this->extended_ms = MBEDTLS_SSL_EXTENDED_MS_ENABLED; break;
                default: return int_print_usage(ret);
            }
        }
        else if( strcmp( p, "etm" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: this->etm = MBEDTLS_SSL_ETM_DISABLED; break;
                case 1: this->etm = MBEDTLS_SSL_ETM_ENABLED; break;
                default: return int_print_usage(ret);
            }
        }
        else if( strcmp( p, "min_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_0;
            else if( strcmp( q, "tls1" ) == 0 )
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_1;
            else if( strcmp( q, "tls1_1" ) == 0 ||
                     strcmp( q, "dtls1" ) == 0 )
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_2;
            else if( strcmp( q, "tls1_2" ) == 0 ||
                     strcmp( q, "dtls1_2" ) == 0 )
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_3;
            else
                return int_print_usage(ret);
        }
        else if( strcmp( p, "max_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_0;
            else if( strcmp( q, "tls1" ) == 0 )
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_1;
            else if( strcmp( q, "tls1_1" ) == 0 ||
                     strcmp( q, "dtls1" ) == 0 )
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_2;
            else if( strcmp( q, "tls1_2" ) == 0 ||
                     strcmp( q, "dtls1_2" ) == 0 )
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_3;
            else
                return int_print_usage(ret);
        }
        else if( strcmp( p, "arc4" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0:     this->arc4 = MBEDTLS_SSL_ARC4_DISABLED;   break;
                case 1:     this->arc4 = MBEDTLS_SSL_ARC4_ENABLED;    break;
                default:    return int_print_usage(ret);
            }
        }
        else if( strcmp( p, "force_version" ) == 0 )
        {
            if( strcmp( q, "ssl3" ) == 0 )
            {
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_0;
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_0;
            }
            else if( strcmp( q, "tls1" ) == 0 )
            {
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_1;
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_1;
            }
            else if( strcmp( q, "tls1_1" ) == 0 )
            {
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_2;
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_2;
            }
            else if( strcmp( q, "tls1_2" ) == 0 )
            {
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_3;
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_3;
            }
            else if( strcmp( q, "dtls1" ) == 0 )
            {
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_2;
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_2;
                this->transport = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
            }
            else if( strcmp( q, "dtls1_2" ) == 0 )
            {
                this->min_version = MBEDTLS_SSL_MINOR_VERSION_3;
                this->max_version = MBEDTLS_SSL_MINOR_VERSION_3;
                this->transport = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
            }
            else
                return int_print_usage(ret);
        }
        else if( strcmp( p, "auth_mode" ) == 0 )
        {
            if( strcmp( q, "none" ) == 0 )
                this->auth_mode = MBEDTLS_SSL_VERIFY_NONE;
            else if( strcmp( q, "optional" ) == 0 )
                this->auth_mode = MBEDTLS_SSL_VERIFY_OPTIONAL;
            else if( strcmp( q, "required" ) == 0 )
                this->auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
            else
                return int_print_usage(ret);
        }
        else if( strcmp( p, "max_frag_len" ) == 0 )
        {
            if( strcmp( q, "512" ) == 0 )
                this->mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_512;
            else if( strcmp( q, "1024" ) == 0 )
                this->mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_1024;
            else if( strcmp( q, "2048" ) == 0 )
                this->mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_2048;
            else if( strcmp( q, "4096" ) == 0 )
                this->mfl_code = MBEDTLS_SSL_MAX_FRAG_LEN_4096;
            else
                return int_print_usage(ret);
        }
        else if( strcmp( p, "trunc_hmac" ) == 0 )
        {
            switch( atoi( q ) )
            {
                case 0: this->trunc_hmac = MBEDTLS_SSL_TRUNC_HMAC_DISABLED; break;
                case 1: this->trunc_hmac = MBEDTLS_SSL_TRUNC_HMAC_ENABLED; break;
                default: return int_print_usage(ret);
            }
        }
        else if( strcmp( p, "hs_timeout" ) == 0 )
        {
            if( ( p = strchr( q, '-' ) ) == NULL )
                return int_print_usage(ret);
            *p++ = '\0';
            this->hs_to_min = atoi( q );
            this->hs_to_max = atoi( p );
            if( this->hs_to_min == 0 || this->hs_to_max < this->hs_to_min )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "recsplit" ) == 0 )
        {
            this->recsplit = atoi( q );
            if( this->recsplit < 0 || this->recsplit > 1 )
                return int_print_usage(ret);
        }
        else if( strcmp( p, "dhmlen" ) == 0 )
        {
            this->dhmlen = atoi( q );
            if( this->dhmlen < 0 )
                return int_print_usage(ret);
        }
        else
            return int_print_usage(ret);
    }
    return true;
}

static bool int_print_usage(int ret)
{
	const int *list;	
    if( ret == 0 )
        ret = 1;

    mbedtls_printf( USAGE );

    list = mbedtls_ssl_list_ciphersuites();
    while( *list )
    {
        mbedtls_printf(" %-42s", mbedtls_ssl_get_ciphersuite_name( *list ) );
        list++;
        if( !*list )
            break;
        mbedtls_printf(" %s\n", mbedtls_ssl_get_ciphersuite_name( *list ) );
        list++;
    }
    mbedtls_printf("\n");
    throw 1;
    return true;
}

bool Options::IsCiphersuiteForced()
{
	return this->force_ciphersuite[0] > 0; 
}

int Options::HandleCiphersuiteRequest()
{
	int ret = 0;
	const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( this->force_ciphersuite[0] );

    if( this->max_version != -1 &&
        ciphersuite_info->min_minor_ver > this->max_version )
    {
        mbedtls_printf("forced ciphersuite not allowed with this protocol version\n");
        ret = 2;
        this->HandleCliArgs(0, NULL);
    }
    if( this->min_version != -1 &&
        ciphersuite_info->max_minor_ver < this->min_version )
    {
        mbedtls_printf("forced ciphersuite not allowed with this protocol version\n");
        ret = 2;
        this->HandleCliArgs(0, NULL);
    }

    /* If the server selects a version that's not supported by
     * this suite, then there will be no common ciphersuite... */
    if( this->max_version == -1 ||
        this->max_version > ciphersuite_info->max_minor_ver )
    {
        this->max_version = ciphersuite_info->max_minor_ver;
    }
    if( this->min_version < ciphersuite_info->min_minor_ver )
    {
        this->min_version = ciphersuite_info->min_minor_ver;
        /* DTLS starts with TLS 1.1 */
        if( this->transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            this->min_version < MBEDTLS_SSL_MINOR_VERSION_2 )
            this->min_version = MBEDTLS_SSL_MINOR_VERSION_2;
    }

    /* Enable RC4 if needed and not explicitly disabled */
    if( ciphersuite_info->cipher == MBEDTLS_CIPHER_ARC4_128 )
    {
        if( this->arc4 == MBEDTLS_SSL_ARC4_DISABLED )
        {
            mbedtls_printf("forced RC4 ciphersuite with RC4 disabled\n");
            ret = 2;
            this->HandleCliArgs(0, NULL);
        }

        this->arc4 = MBEDTLS_SSL_ARC4_ENABLED;
    }

    return ret;
}

bool Options::IsPSKEnabled()
{
  return strcmp(this->psk, "");
}

void Options::UnhexifyPSK(unsigned char *psk, size_t psk_len)
{
    if( strlen( this->psk ) )
    {
        unsigned char c;
        size_t j;

        if( strlen( this->psk ) % 2 != 0 )
        {
            mbedtls_printf("pre-shared key not valid hex\n");
            throw 1;
        }

        psk_len = strlen( this->psk ) / 2;

        for( j = 0; j < strlen( this->psk ); j += 2 )
        {
            c = this->psk[j];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                mbedtls_printf("pre-shared key not valid hex\n");
                throw 1;
            }
            psk[ j / 2 ] = c << 4;

            c = this->psk[j + 1];
            if( c >= '0' && c <= '9' )
                c -= '0';
            else if( c >= 'a' && c <= 'f' )
                c -= 'a' - 10;
            else if( c >= 'A' && c <= 'F' )
                c -= 'A' - 10;
            else
            {
                mbedtls_printf("pre-shared key not valid hex\n");
                throw 1;
            }
            psk[ j / 2 ] |= c;
        }
    }
}

void Options::SslAlpn(const char** alpn_list)
{
    char *p;
    if( this->alpn_string != NULL )
    {
        p = (char *) this->alpn_string;
        int i = 0;

        /* Leave room for a final NULL in alpn_list */
        while( i < (int) sizeof alpn_list - 1 && *p != '\0' )
        {
            alpn_list[i++] = p;

            /* Terminate the current string and move on to next one */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';
        }
    }
}
