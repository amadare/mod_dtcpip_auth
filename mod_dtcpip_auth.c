// COPYRIGHT_BEGIN
// DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
//
// Copyright (C) 2013  Cable Television Laboratories, Inc.
// Contact: http://www.cablelabs.com/
//
// This is free software; you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CABLE TELEVISION LABORATORIES
// INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
// COPYRIGHT_END

#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "s_dtcp_interface.h"
#include "apr_strings.h"
#include "mod_dtcpip_auth.h"
#include "mod_ssl.h"
#include <openssl/ssl.h>

static const char dtcpEncryptFilterName[]="DtcpEncryptFilter";
//length and type
static const unsigned char auth_ext_data[]={1, TLSEXT_AUTHZDATAFORMAT_dtcp};
static int g_bRandomNumInitialized = 0;

typedef struct {
    char *library_path;
    char *key_storage_dir;
    int send_certs;
    int require_reneg;
    int enable_dtcp_encryption;
    int dtcp_encryption_port;
} dtcpip_auth_config_rec;

struct filter_state {
   apr_bucket_brigade *input_brigade;
   apr_bucket_brigade *encrypted_brigade;
   int session_handle;
};

static void *create_dtcpip_auth_srv_config(apr_pool_t *p, server_rec *s)
{
    dtcpip_auth_config_rec *conf = NULL;

    conf = apr_pcalloc(p, sizeof(*conf));

    conf->library_path = NULL;
    conf->key_storage_dir = NULL;
    conf->send_certs = 0;
    conf->require_reneg = 0;
    conf->enable_dtcp_encryption = 0;
    conf->dtcp_encryption_port = 0;
    return conf;
}

static const command_rec dtcpip_auth_cmds[] =
{
    AP_INIT_TAKE1("DTCPLibraryPath", set_library_path,
        NULL, OR_ALL, "Path to DTCP library"),
    AP_INIT_TAKE1("DTCPKeyStorageDir", set_key_dir,
        NULL, OR_ALL, "Directory containing DTCP keys/certs"),
    AP_INIT_FLAG("DTCPSendCerts", set_send_certs,
        NULL, OR_ALL, "Send DTCP and X509 certs in supplemental data"),
    AP_INIT_FLAG("DTCPRequireReneg", set_require_reneg,
        NULL, OR_ALL, "Send TLS extensions after renegotiation"),
    AP_INIT_FLAG("DTCPEnableDTCPEncryption", set_enable_dtcp_encryption,
        NULL, OR_ALL, "Support DTCP-based encryption of content (entire contents loaded in memory prior to encryption)"),
    AP_INIT_TAKE1("DTCPEncryptionPort", set_dtcp_encryption_port,
        NULL, OR_ALL, "Port supporting DTCP-based encryption"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA dtcpip_auth_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_dtcpip_auth_srv_config,
    NULL,
    dtcpip_auth_cmds,
    mod_dtcpip_auth_register_hooks,
};

static apr_status_t dtcpEncryptFilterOutFilter(ap_filter_t *filter,
                                        apr_bucket_brigade *in_brigade)
{
    apr_bucket *in_bucket;
    request_rec *r = filter->r;
    conn_rec *c = r->connection;
    int is_eos = 0;
    struct filter_state *state;

    if (APR_BRIGADE_EMPTY(in_brigade)) {
        return APR_SUCCESS;
    }

    state = filter->ctx;
    if (state == NULL)
    {
        int session_handle = -1;
        int result = DTCPIPSrc_Open(&session_handle, 0);
        if (result)
        {
            fprintf(stderr, "DTCPIPSrc_Open failed - %d\n", result);
            fflush(stderr);
            return APR_SUCCESS;
        }
        else
        {
            filter->ctx = state = apr_palloc(r->pool, sizeof *state);
            state->session_handle = session_handle;
            state->input_brigade = apr_brigade_create(r->pool, c->bucket_alloc);
            state->encrypted_brigade = apr_brigade_create(r->pool, c->bucket_alloc);
        }
    }

    //collect all input into a single brigade and encrypt the content of all buckets in a single call to allocencrypt
    for (in_bucket = APR_BRIGADE_FIRST(in_brigade);
         in_bucket != APR_BRIGADE_SENTINEL(in_brigade);
         in_bucket = APR_BUCKET_NEXT(in_bucket))
    {
        const char *data = 0;
        apr_size_t len = 0;
        char *buf = 0;
        apr_size_t n = 0;
        apr_bucket *out_bucket = 0;


        if(APR_BUCKET_IS_EOS(in_bucket))
        {
            is_eos = 1;
            continue;
        }

        apr_bucket_read(in_bucket, &data, &len, APR_BLOCK_READ);

        //populate a new bucket from the input bucket
        buf = apr_bucket_alloc(len, c->bucket_alloc);
        for(n=0 ; n < len ; ++n)
        {
            buf[n] = data[n];
        }

        out_bucket = apr_bucket_pool_create(buf, len, r->pool,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(state->input_brigade, out_bucket);
    }

    if (is_eos)
    {
        char *encrypted_data = 0;
        unsigned int encrypted_size = 0;
        apr_status_t status = 0;
        char *all_data = 0;
        apr_size_t all_data_size = 0;
        int result = 0;
        apr_bucket *encrypted_bucket_1 = 0;
        apr_bucket *encrypted_bucket_2 = 0;
        apr_bucket *eos_bucket = 0;
        apr_size_t encrypted_bucket_size = 0;
        char *buf = 0;
        apr_size_t n = 0;

        status = apr_brigade_pflatten(state->input_brigade,&all_data, &all_data_size, r->pool);

        if (status != APR_SUCCESS)
        {
            fprintf(stderr, "unable to retrieve data to encrypt\n");
            fflush(stderr);
            return status;
        }
        if (all_data_size == 0)
        {
            fprintf(stderr, "no content to encrypt\n");
            fflush(stderr);
            return APR_SUCCESS;
        }

        int encrypt = DTCPIPSrc_AllocEncrypt(state->session_handle, 0x03,
        (char *)all_data, all_data_size, &encrypted_data, &encrypted_size);

        fprintf(stderr, "encrypt result %d - input length: %d, encrypted length: %d\n", encrypt, all_data_size, encrypted_size);
        fflush(stderr);

        if (encrypt)
        {
            return APR_SUCCESS;
        }

        //split encrypted data across two buckets in order to ensure chunked transfer encoding is supported
        encrypted_bucket_size = encrypted_size / 2;

        buf = apr_bucket_alloc(encrypted_size, c->bucket_alloc);
        for(n=0 ; n < encrypted_size ; ++n)
        {
            buf[n] = encrypted_data[n];
        }

        encrypted_bucket_1 = apr_bucket_pool_create(buf, encrypted_bucket_size, r->pool,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(state->encrypted_brigade, encrypted_bucket_1);

        //always call ap_pass_brigade with a a brigade which contains at least one (non-EOS) bucket prior to calling
        //ap_pass_brigade which does include an EOS bucket in order to avoid a content-length header,
        //facilitating chunked transfer encoding
        ap_pass_brigade(filter->next,state->encrypted_brigade);

        //now send the remaining data in the second call to ap_pass_brigade
        encrypted_bucket_2 = apr_bucket_pool_create((buf + encrypted_bucket_size), (encrypted_size - encrypted_bucket_size), r->pool,
                                         c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(state->encrypted_brigade, encrypted_bucket_2);

        //include an EOS bucket
        eos_bucket = apr_bucket_eos_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_TAIL(state->encrypted_brigade, eos_bucket);

        result = DTCPIPSrc_Free(encrypted_data);
        if (result)
        {
            fprintf(stderr, "DTCPIPSrc_Free - result %d\n", result);
            fflush(stderr);
        }

        result = DTCPIPSrc_Close(state->session_handle);
        if (result)
        {
            fprintf(stderr, "DTCPIPSrc_Close - result %d\n", result);
            fflush(stderr);
        }

        apr_brigade_cleanup(in_brigade);
        apr_brigade_cleanup(state->input_brigade);
        return ap_pass_brigade(filter->next,state->encrypted_brigade);
    }
    return APR_SUCCESS;
}

const char *set_library_path(cmd_parms* cmd, void *cfg, const char* arg)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module); 
    config->library_path = (char *)arg;
    return NULL;
}

const char *set_key_dir(cmd_parms* cmd, void *cfg, const char* arg)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module); 
    config->key_storage_dir = (char *)arg;
    return NULL;
}

const char *set_send_certs(cmd_parms *cmd,
                                    void *dcfg,
                                    int flag)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module);
    config->send_certs = flag;

    return NULL;
}

const char *set_require_reneg(cmd_parms *cmd,
                                    void *dcfg,
                                    int flag)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module);
    config->require_reneg = flag;

    return NULL;
}

const char *set_enable_dtcp_encryption(cmd_parms *cmd,
                                    void *dcfg,
                                    int flag)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module);
    config->enable_dtcp_encryption = flag;

    return NULL;
}

const char *set_dtcp_encryption_port(cmd_parms *cmd,
                                    void *dcfg,
                                    const char* arg)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module);
    config->dtcp_encryption_port = apr_atoi64(arg);

    return NULL;
}

static int mod_dtcpip_auth_handler (request_rec *r)
{
    fprintf(stderr,"mod_dtcpip_auth_handler: \n");
    fflush(stderr);

    return DECLINED;
}

static int mod_dtcpip_auth_post_config (apr_pool_t *pconf, apr_pool_t *plog,
    apr_pool_t *ptemp, server_rec *s)
{
    void *data = NULL;
    const char *key = "dummy_post_config";

    // Only perform post-config processing once
    // See http://wiki.apache.org/httpd/ModuleLife
    apr_pool_userdata_get(&data, key, s->process->pool);
    if (data == NULL) {
        apr_pool_userdata_set((const void *)1, key, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    APR_OPTIONAL_FN_TYPE(ssl_register_srv_tls_ext_type) *register_srv_tls_ext = NULL;
    APR_OPTIONAL_FN_TYPE(ssl_register_srv_tls_suppdata_type) *register_srv_supp_data = NULL;
    int nReturn = 0;
    dtcpip_auth_config_rec *conf = ap_get_module_config(s->module_config, &dtcpip_auth_module);
    fprintf(stderr,"mod_dtcpip_auth_post_config: library_path = %s\n",
        conf->library_path);
    fprintf(stderr,"mod_dtcpip_auth_post_config: key_storage_dir = %s\n",
        conf->key_storage_dir);
    fprintf(stderr,"mod_dtcpip_auth_post_config: require_reneg = %d\n",
        conf->require_reneg);
    fprintf(stderr,"mod_dtcpip_auth_post_config: send_certs = %d\n",
        conf->send_certs);
    fprintf(stderr,"mod_dtcpip_auth_post_config: enable_dtcp_encryption = %d\n",
        conf->enable_dtcp_encryption);
    fprintf(stderr,"mod_dtcpip_auth_post_config: dtcp_encryption_port = %d\n",
        conf->dtcp_encryption_port);

    fflush(stderr);

    nReturn = initDTCP(conf->library_path, conf->key_storage_dir);
    fprintf(stderr,"mod_dtcpip_auth_post_config: initDTCP returned %d\n", nReturn);
    fflush(stderr);

    if (conf->enable_dtcp_encryption)
    {
        nReturn = DTCPIPSrc_Init(conf->dtcp_encryption_port);
        fprintf(stderr,"mod_dtcpip_auth_post_config - DTCP encryption enabled - DTCPIPSrc_Init result: %d\n", nReturn);
        fflush(stderr);
    } else {
        fprintf(stderr,"mod_dtcpip_auth_post_config: DTCP encryption not enabled\n");
        fflush(stderr);
    }

    srand((unsigned)time(NULL));

    register_srv_tls_ext = APR_RETRIEVE_OPTIONAL_FN(ssl_register_srv_tls_ext_type);
    if (register_srv_tls_ext == NULL)
    {
        fprintf(stderr,"FAILED retrieving ssl_register_srv_tls_ext_type ptr\n");
        fflush(stderr);
        return OK;
    }
    nReturn = register_srv_tls_ext(s, TLSEXT_TYPE_client_authz, NULL);

    nReturn = register_srv_tls_ext(s, TLSEXT_TYPE_server_authz, NULL);

    register_srv_supp_data=APR_RETRIEVE_OPTIONAL_FN(ssl_register_srv_tls_suppdata_type);
    if (register_srv_supp_data == NULL)
    {
        fprintf(stderr,"FAILED retrieving ssl_register_srv_tls_ext_type ptr\n");
        fflush(stderr);
        return OK;
    }
    nReturn = register_srv_supp_data(s, 16386, NULL);

    return OK;
}

static int tls_ext_receive(conn_rec *c,
                           void *session,
                           unsigned short ext_type,
                           const unsigned char *in,
                           unsigned short inlen,
                           int *al, void *arg)
{
    if (ext_type == TLSEXT_TYPE_client_authz) {
        if (memchr(in, TLSEXT_AUTHZDATAFORMAT_dtcp, inlen) != NULL)
        {
            apr_table_setn(c->notes, "DTCP_CLIENT_AUTHZ_RECEIVED", "1");
        }
    }
    if (ext_type == TLSEXT_TYPE_server_authz) {
        if (memchr(in, TLSEXT_AUTHZDATAFORMAT_dtcp, inlen) != NULL)
        {
            apr_table_setn(c->notes, "DTCP_SERVER_AUTHZ_RECEIVED", "1");
        }
    }
    fprintf(stderr,"mod_dtcpip_auth tls_ext_receive - type %d\n", ext_type);
    fflush(stderr);
    return OK;
}

static int tls_ext_generate(conn_rec *c, void *session,
                            unsigned short ext_type,
                            const unsigned char **out,
                            unsigned short *outlen,
                            int *al, void *arg)
{
    SSL *ssl = (SSL *)session;
    dtcpip_auth_config_rec *config = NULL;
    config = ap_get_module_config(c->base_server->module_config, &dtcpip_auth_module);

    //ensure reneg is full handshake
    SSL_set_options(ssl, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    if (apr_table_get(c->notes, "DTCP_CLIENT_AUTHZ_RECEIVED") && apr_table_get(c->notes, "DTCP_SERVER_AUTHZ_RECEIVED")) {
        if (TLSEXT_TYPE_client_authz == ext_type || TLSEXT_TYPE_server_authz == ext_type) {
            if (!config->require_reneg || (config->require_reneg && SSL_num_renegotiations(ssl))) {
                *out = auth_ext_data;
                *outlen = sizeof(auth_ext_data);
                fprintf(stderr,"mod_dtcpip_auth tls_ext_generate - setting - type %d\n", ext_type);
                fflush(stderr);
                if (TLSEXT_TYPE_client_authz == ext_type) {
                    apr_table_setn(c->notes, "DTCP_CLIENT_AUTHZ_SENT", "1");
                }
                if (TLSEXT_TYPE_server_authz == ext_type) {
                    apr_table_setn(c->notes, "DTCP_SERVER_AUTHZ_SENT", "1");
                }
                return OK;
            } else {
                fprintf(stderr,"mod_dtcpip_auth tls_ext_generate - reneg required\n");
                fflush(stderr);
            }
        } else {
            fprintf(stderr,"mod_dtcpip_auth tls_ext_generate - unknown extension type received\n");
            fflush(stderr);
        }
    } else {
        fprintf(stderr,"mod_dtcpip_auth tls_ext_generate - both TLS extensions required\n");
        fflush(stderr);
    }
    return DECLINED;
}

static int tls_suppdata_receive(conn_rec *c, void *session,
                                unsigned short suppdata_type,
                                const unsigned char *in,
                                unsigned short inlen,
                                int *al, void *arg)
{
    int ret = 0;
    ret = validate_dtcp_suppdata(in, inlen, c);
    fprintf(stderr,"mod_dtcpip_auth tls_suppdata_receive - type %d - validate result %d\n", suppdata_type, ret);
    fflush(stderr);
    if (ret == 0)
    {
        apr_table_setn(c->notes, "DTCP_VALIDATION_SUCCESSFUL", "1");
        fprintf(stderr,"setting dtcp_validation_successful to 1\n");
        fflush(stderr);
        return OK;
    }
    else
    {
        *al = SSL_AD_DECODE_ERROR;
        return 1;
    }
}

static int tls_suppdata_generate(conn_rec *c, void *session,
                                 unsigned short suppdata_type,
                                 const unsigned char **out,
                                 unsigned short *outlen,
                                 int *al, void *arg)
{
    SSL *ssl = (SSL *)session;
    X509 *cert = NULL;
    int ret;
    dtcpip_auth_config_rec *config = NULL;

    config = ap_get_module_config(c->base_server->module_config, &dtcpip_auth_module);

    if (apr_table_get(c->notes, "DTCP_CLIENT_AUTHZ_SENT") &&
        apr_table_get(c->notes, "DTCP_SERVER_AUTHZ_SENT"))
    {
        //send dtcp supplemental data
        cert = SSL_get_certificate(ssl);
        ret = format_dtcp_suppdata(out, outlen, cert, config->send_certs, c);
        fprintf(stderr,"mod_dtcpip_auth tls_suppdata_generate - type %d - result %d\n", suppdata_type, ret);
        fflush(stderr);
        if (ret == 0) {
            return OK;
        } else {
            //error
            return 1;
        }
    }
    fprintf(stderr,"mod_dtcpip_auth tls_suppdata_generate - not generating\n");
    fflush(stderr);

    return DECLINED;
}

static int handshake_complete(conn_rec *c, void *session, long num_renegotiations)
{
    //NOTE: returning OK from this function initiates renegotiation
    dtcpip_auth_config_rec *config = NULL;

    config = ap_get_module_config(c->base_server->module_config, &dtcpip_auth_module);
    fprintf(stderr,"mod_dtcpip_auth handshake_complete check\n");
    fflush(stderr);
    if (!num_renegotiations)
    {
        fprintf(stderr,"mod_dtcpip_auth handshake_complete - ZERO renegotiations\n");
        fflush(stderr);

        if (config->require_reneg)
        {
            fprintf(stderr,"mod_dtcpip_auth handshake_complete - require_reneg and no reneg yet\n");
            fflush(stderr);
            return OK;
        }
        if (apr_table_get(c->notes, "DTCP_CLIENT_AUTHZ_SENT") &&
            apr_table_get(c->notes, "DTCP_SERVER_AUTHZ_SENT"))
        {
            fprintf(stderr,"mod_dtcpip_auth handshake_complete - sent both authz types\n");
            fflush(stderr);

            if (!apr_table_get(c->notes, "DTCP_PEER_X509"))
            {
                fprintf(stderr,"mod_dtcpip_auth handshake_complete - no peer x509 in suppdata and no reneg yet\n");
                fflush(stderr);
                return OK;
            }
        }
    }
    return DECLINED;
}

static int propagate_validation(request_rec * r)
{
    const char * dtcp_authentication;
    dtcp_authentication = apr_table_get(r->connection->notes, "DTCP_VALIDATION_SUCCESSFUL");
    if (!dtcp_authentication)
    {
        dtcp_authentication = "0";
    }

    apr_table_setn(r->subprocess_env, "DTCP_VALIDATION_SUCCESSFUL", dtcp_authentication);
    fprintf(stderr, "subprocess env dtcp validation successful set to %s\n", dtcp_authentication);
    fflush(stderr);
}

static void mod_dtcpip_auth_register_hooks (apr_pool_t *p)
{
    ap_hook_handler(mod_dtcpip_auth_handler, NULL, NULL, APR_HOOK_LAST);
    ap_hook_fixups(propagate_validation, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config (mod_dtcpip_auth_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    ap_register_output_filter(dtcpEncryptFilterName, dtcpEncryptFilterOutFilter, NULL,
                              AP_FTYPE_RESOURCE);

    APR_OPTIONAL_HOOK(ssl, handshake_complete, handshake_complete, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, srv_tls_ext_generate, tls_ext_generate, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, srv_tls_ext_receive, tls_ext_receive, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, srv_tls_suppdata_receive, tls_suppdata_receive, NULL, NULL, APR_HOOK_MIDDLE);
    APR_OPTIONAL_HOOK(ssl, srv_tls_suppdata_generate, tls_suppdata_generate, NULL, NULL, APR_HOOK_MIDDLE);
}

static int format_dtcp_suppdata(const unsigned char **suppdata, unsigned short *suppdata_len, X509 *cert,
                                int send_certs, conn_rec *c)
{
    unsigned int pSignOffset = 0;
    unsigned int uNumBytesToSign = 0;
    int ret = 0;
    unsigned char pLocalCert[1000];
    unsigned int uLocalCertSize = 1000;
    unsigned char pSignature[1000];
    unsigned int uSignatureSize = 1000;
    unsigned char *x509Cert = NULL;
    unsigned char *p = NULL;
    int x509CertLength;
    size_t i = 0;
    size_t index = 0;
    unsigned short encodedLength = 0;
    unsigned char *suppdata_to_send = NULL;
    unsigned char *nonce = NULL;
    size_t NONCE_SIZE = 32;
    //type, length and nonce
    if (send_certs && cert)
    {
        ret = DTCPIPAuth_GetLocalCert (pLocalCert, &uLocalCertSize);
        if (ret != 0)
        {
            fprintf(stderr, "failed to retrieve local cert: %d\n", ret);
            goto err;
        }
        x509CertLength = i2d_X509(cert, NULL);
        x509Cert = apr_palloc(c->pool, x509CertLength);
    }

    suppdata_to_send=apr_palloc(c->pool, sizeof(char *) * (1 + 2 + 32)
                                + sizeof(char *)*uLocalCertSize + sizeof(char *)*2
                                + sizeof(char *)*x509CertLength + sizeof(char *)*2
                                + sizeof(char *)*uSignatureSize);
    if (suppdata_to_send == NULL)
    {
        fprintf(stderr, "failed to allocate memory for supplemental data\n");
        goto err;
    }

    suppdata_to_send[0] = TLSEXT_AUTHZDATAFORMAT_dtcp;
    index += 3;

    // generate nonce and persist it for later validation
    if (g_bRandomNumInitialized == 0)
    {
        srand((unsigned)time(NULL));
        g_bRandomNumInitialized = 1;
    }

    nonce = apr_pcalloc(c->pool, NONCE_SIZE);
    for (i=0; i<8; i++)
    {
        int randomNum = rand();
        memcpy (nonce + 4*i, &randomNum, 4);
    }

    //include nonce
    pSignOffset = index;
    uNumBytesToSign = 32;

    memcpy (suppdata_to_send + index, nonce, 32);
    index += 32;

    if (send_certs && cert)
    {
        uNumBytesToSign += 2 + uLocalCertSize;

        /*add DTCP cert size*/
        suppdata_to_send[index++] = (uLocalCertSize >> 8) & 0xff;
        suppdata_to_send[index++] = uLocalCertSize & 0xff;

        memcpy (suppdata_to_send + index, pLocalCert, uLocalCertSize);
        index += uLocalCertSize;

        if (x509Cert == NULL)
        {
            fprintf(stderr, "failed to allocate memory for x509 cert data\n");
            goto err;
        }

        /*add x509 cert size*/
        suppdata_to_send[index++] = (x509CertLength >> 8) & 0xff;
        suppdata_to_send[index++] = x509CertLength & 0xff;

        p = x509Cert;
        i2d_X509(cert, &p);
        memcpy (suppdata_to_send + index, x509Cert, x509CertLength);
        index += x509CertLength;
        uNumBytesToSign += 2 + x509CertLength;

        ret =  DTCPIPAuth_SignData(suppdata_to_send + pSignOffset, uNumBytesToSign, pSignature,
                                   &uSignatureSize);

        if (ret != 0)
        {
            fprintf(stderr, "failed to sign data: %d\n", ret);
            goto err;
        }

        memcpy (suppdata_to_send + index, pSignature, uSignatureSize);
        index += uSignatureSize;
    }
    else
    {
        //set dtcp and x509 cert lengths to zero
        suppdata_to_send[index++] = 0;
        suppdata_to_send[index++] = 0;
        suppdata_to_send[index++] = 0;
        suppdata_to_send[index++] = 0;
    }

    *suppdata_len = index;

    // fill in length
    encodedLength = *suppdata_len - 3;
    suppdata_to_send[1]  = encodedLength >> 8 & 0xff;
    suppdata_to_send[2]  = encodedLength & 0xff;
    *suppdata = suppdata_to_send;
    apr_table_setn(c->notes, "DTCP_NONCE", nonce);
//    fprintf(stderr, "STORING NONCE\n");
//    for (i=0; i<NONCE_SIZE; i++)
//    {
//        fprintf (stderr, "0x%02x ", nonce[i]);
//        if (i%8 == 7)
//        {
//            fprintf (stderr, "\n");
//        }
//    }
//    fprintf (stderr, "\n");

    fflush(stderr);
    return 0;

err:
    fflush(stderr);
    return -1;
}

static int validate_dtcp_suppdata(const unsigned char *suppdata, unsigned short suppdata_len, conn_rec *c)
{
    unsigned int pSignOffset = 0;
    size_t uNumBytesSigned = 0;
    unsigned char *pRemoteCert = NULL;
    size_t uRemoteCertSize = 0;
    unsigned char pSignature[40];
    size_t uSignatureSize = 40;
    size_t x509Size = 0;
    unsigned char nonce[32];
    int ret;
    size_t i = 0;
    const unsigned char *sent_nonce = NULL;
    char *peer_x509 = NULL;
    //length stored in char array
    char *peer_x509_length = NULL;

    //type + length
    unsigned int index = 3;

    //include nonce
    pSignOffset = index;
    uNumBytesSigned = 32;

    memcpy (nonce, suppdata + index, 32);
    index += 32;
//    fprintf(stderr, "RECEIVED NONCE\n");
//    for (i=0; i<32; i++)
//    {
//        fprintf (stderr, "0x%02x ", nonce[i]);
//        if (i%8 == 7)
//        {
//            fprintf (stderr, "\n");
//        }
//    }
//    fprintf (stderr, "\n");

    // compare nonce to nonce sent previously
    sent_nonce = apr_table_get(c->notes, "DTCP_NONCE");
//    fprintf(stderr, "SENT NONCE\n");
//    for (i=0; i<32; i++)
//    {
//        fprintf (stderr, "0x%02x ", sent_nonce[i]);
//        if (i%8 == 7)
//        {
//            fprintf (stderr, "\n");
//        }
//    }
//    fprintf (stderr, "\n");

    for (i=0; i<32; i++)
    {
        if (sent_nonce[i] != nonce[i])
        {
            fprintf(stderr, "validate_dtcp_suppdata: validation failed: invalid nonce\n");
            return -1;
        }
    }

    //next two bytes are dtcp cert length - always sent by client
    uRemoteCertSize = (suppdata[index] << 8) | suppdata[index+1];
    index += 2;

    uNumBytesSigned += 2 + uRemoteCertSize;

    pRemoteCert = apr_palloc(c->pool, uRemoteCertSize);

    memcpy (pRemoteCert, suppdata + index, uRemoteCertSize);
    index += uRemoteCertSize;

    //suppdata is received before peer cert - check peer cert outside of the callback
    x509Size = (suppdata[index] << 8) | suppdata[index+1];
    index += 2;
    uNumBytesSigned +=2;
    if (x509Size > 0)
    {
        peer_x509 = apr_palloc(c->pool, x509Size);
        if (peer_x509 == NULL)
        {
            fprintf(stderr, "failed to allocate memory for peer suppdata x509\n");
            goto err;
        }
        memcpy (peer_x509, suppdata + index, x509Size);
        peer_x509_length = apr_itoa(c->pool, x509Size);
        index += x509Size;

        uNumBytesSigned += x509Size;
        apr_table_setn(c->notes, "DTCP_PEER_X509", peer_x509);
        apr_table_setn(c->notes, "DTCP_PEER_X509_LENGTH", peer_x509_length);
    }

    memcpy (pSignature, suppdata + index, uSignatureSize);
    index += uSignatureSize;

    //        printf("num signed bytes %d\n", uNumBytesSigned);
    //        printf("uSignatureSize = %d\n", uSignatureSize);
    //        for (i=0; i<uSignatureSize; i++)
    //        {
    //            printf ("0x%02x ", pSignature[i]);
    //            if (i%8 == 7)
    //            {
    //                printf ("\n");
    //            }
    //        }
    //        printf ("\n");
    // validate signature
    ret =  DTCPIPAuth_VerifyData((unsigned char *)suppdata + pSignOffset, uNumBytesSigned, pSignature,
                                 pRemoteCert);

    if (ret != 0)
    {
        fprintf(stderr, "verify data failed: %d\n", ret);
        goto err;
    }

    // validate cert
    ret =  DTCPIPAuth_VerifyRemoteCert(pRemoteCert);

    if (ret != 0)
    {
        fprintf(stderr, "verify remote cert failed: %d\n", ret);
        goto err;
    }

    fprintf(stderr, "DTCP validation successful\n");
    fflush(stderr);
    return 0;

err:
    fflush(stderr);
    return -1;
}



