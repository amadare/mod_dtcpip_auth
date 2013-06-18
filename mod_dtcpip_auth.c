// COPYRIGHT_BEGIN
//  DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
//
//  Copyright (C) 2012-2013, Cable Television Laboratories, Inc.
//
//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, version 2. This program is distributed
//  in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
//  even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
//  PURPOSE. See the GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License along
//  with this program.  If not, see  <http://www.gnu.org/licenses/>.
//
//  Please contact CableLabs if you need additional information or
//  have any questions.
//
//      CableLabs
//      858 Coal Creek Cir
//      Louisville, CO 80027-9750
//      303 661-9100
//      oc-mail@cablelabs.com
//
//  If you or the company you represent has a separate agreement with CableLabs
//  concerning the use of this code, your rights and obligations with respect
//  to this code shall be as set forth therein. No license is granted hereunder
//  for any other purpose.
// COPYRIGHT_END

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "s_dtcp_interface.h"
#include "mod_dtcpip_auth.h"
#include <openssl/ssl.h>
#include <time.h>
#include <apr_strings.h>

static void mod_dtcpip_auth_register_hooks (apr_pool_t *p);

const char* set_dtcp_dll_path(cmd_parms* cmd, void *cfg, const char* arg);
const char* set_dtcp_key_dir(cmd_parms* cmd, void *cfg, const char* arg);

// GORP: get this from tls1.h instead of here
#define TLSEXT_AUTHZDATAFORMAT_dtcp 225
static unsigned char g_stored_nonce[32];


typedef struct {
    char *dtcp_dll_path;
    char *dtcp_key_storage_dir;
} dtcpip_auth_config_rec;


static void *create_dtcpip_auth_srv_config(apr_pool_t *p, server_rec *s)
{
    dtcpip_auth_config_rec *conf = NULL;
//    fprintf (stderr, "Inside create_dtcpip_auth_srv_config\n");
//    fflush (stderr);
    
    conf = apr_pcalloc(p, sizeof(*conf));

    conf->dtcp_dll_path = NULL;
    conf->dtcp_key_storage_dir = NULL;

    return conf;
}

static const command_rec dtcpip_auth_cmds[] =
{
    AP_INIT_TAKE1("DTCPIPAuth_DTCP_DLL_Path", set_dtcp_dll_path,
        NULL, OR_ALL, "Path of DTCP DLL"), 
    AP_INIT_TAKE1("DTCPIPAuth_DTCP_Key_Storage_Dir", set_dtcp_key_dir,
        NULL, OR_ALL, "Directory for DTCP keys/certs"),
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

const char* set_dtcp_dll_path(cmd_parms* cmd, void *cfg, const char* arg)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module); 
    config->dtcp_dll_path = (char *)arg;
    return NULL;
}

const char* set_dtcp_key_dir(cmd_parms* cmd, void *cfg, const char* arg)
{
    dtcpip_auth_config_rec *config = ap_get_module_config (cmd->server->module_config, &dtcpip_auth_module); 
    config->dtcp_key_storage_dir = (char *)arg;
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
    int nReturn = 0;

    fprintf(stderr,"Inside mod_dtcpip_auth_post_config\n");
    fflush(stderr);

    dtcpip_auth_config_rec *conf = ap_get_module_config(s->module_config, &dtcpip_auth_module);
    fprintf(stderr,"mod_dtcpip_auth_post_config: dtcp_dll_path = %s\n", 
        conf->dtcp_dll_path);
    fprintf(stderr,"mod_dtcpip_auth_post_config: dtcp_key_storage_dir = %s\n", 
        conf->dtcp_key_storage_dir);
    fflush(stderr);

    nReturn = initDTCP(conf->dtcp_dll_path, conf->dtcp_key_storage_dir);
    fprintf(stderr,"mod_dtcpip_auth_post_config: initDTCP returned %d\n", nReturn);
    fflush(stderr);

    srand((unsigned)time(NULL)); 

    return OK;
}

static void mod_dtcpip_auth_register_hooks (apr_pool_t *p)
{
    ap_hook_handler(mod_dtcpip_auth_handler, NULL, NULL, APR_HOOK_LAST);
    ap_hook_post_config (mod_dtcpip_auth_post_config, NULL, NULL, APR_HOOK_MIDDLE); 

    APR_REGISTER_OPTIONAL_FN(validate_dtcp_suppdata);
    APR_REGISTER_OPTIONAL_FN(format_dtcp_suppdata);
}

int format_dtcp_suppdata(unsigned char *suppdata, unsigned short *suppdata_len, unsigned char *pServerSuppdata, int isServer, int sendCert, X509 *cert, conn_rec *c)
{
    // suppdata array has already been allocated by caller
    int nReturnCode = 0;
    unsigned char *pStartOfBytesToSign = 0;
    unsigned int uNumBytesToSign = 0;
    unsigned char pLocalCert[1000];
    unsigned int uLocalCertSize = 1000;
    unsigned char pSignature[1000];
    unsigned int uSignatureSize = 1000;
    unsigned char *x509Cert, *p;
    int x509CertLength;
    int i=0;
    int index = 0;
    unsigned short encodedLength = 0;

    fprintf(stderr, "format_dtcp_suppdata\n");
    fflush(stderr);

    suppdata[0] = TLSEXT_AUTHZDATAFORMAT_dtcp;
    index += 3;

    for (i=0; i<8; i++)
    {
        int randonNum = rand();
        memcpy (g_stored_nonce + 4*i, &randonNum, 4);
    }

    memcpy (suppdata + index, g_stored_nonce, 32);
//    apr_table_setn(c->notes, "DTCP_NONCE", g_stored_nonce);
    index += 32;
    
    nReturnCode = DTCPIPAuth_GetLocalCert (pLocalCert, &uLocalCertSize);
    fprintf(stderr, "DTCPIPAuth_GetLocalCert returned %d, size %d\n", nReturnCode, uLocalCertSize);
    fflush(stderr);
    if (nReturnCode != 0)
    {
        return -1;
    }

/*    printf("uLocalCertSize = %d\n", uLocalCertSize);
    printf("LocalCert:\n");
    for (i=0; i<uLocalCertSize; i++)
	{
        printf ("0x%02x ", pLocalCert[i]);
        if (i%8 == 7)
        {
            printf ("\n");
        }
    }
    printf ("\n");
    */

    /*add DTCP cert size*/
    pStartOfBytesToSign = suppdata + index;
    uNumBytesToSign = 2 + uLocalCertSize;
    suppdata[index++] = (uLocalCertSize >> 8) & 0xff;
    suppdata[index++] = uLocalCertSize & 0xff;

    memcpy (suppdata + index, pLocalCert, uLocalCertSize);
    index += uLocalCertSize;

    if (sendCert && cert)
    {
        x509CertLength = i2d_X509(cert, NULL);
	    x509Cert = apr_pcalloc(c->pool, x509CertLength) ;
        if (x509Cert == NULL)
        {
            fprintf(stderr, "Unable to allocate buffer for x509 cert data\n");
            fflush(stderr);
            return -1;
        }
        fprintf(stderr, "x509 cert size %d\n", x509CertLength);
        fflush(stderr);
        /*add x509 cert size*/
        suppdata[index++] = (x509CertLength >> 8) & 0xff;
        suppdata[index++] = x509CertLength & 0xff;

        p = x509Cert;
        i2d_X509(cert, &p);
        memcpy (suppdata + index, x509Cert, x509CertLength);
        index += x509CertLength;
        uNumBytesToSign += 2 + x509CertLength;
    }
    else
    {
       fprintf(stderr, "-send_dtcp_cert not set or no cert available\n");
       fflush(stderr);
    }
	

    nReturnCode =  DTCPIPAuth_SignData(pStartOfBytesToSign, uNumBytesToSign, pSignature, &uSignatureSize);
    fprintf(stderr, "DTCPIPAuth_SignData returned %d\n", nReturnCode);
    fflush(stderr);
    if (nReturnCode != 0)
    {
        return -1;
    }

/*    printf("uSignatureSize = %d\n", uSignatureSize);
    printf("Signature:\n");
    for (i=0; i<uSignatureSize; i++)
    {
        printf ("0x%02x ", pSignature[i]);
        if (i%8 == 7)
        {
            printf ("\n");
        }
    }
    printf ("\n");
    */

    memcpy (suppdata + index, pSignature, uSignatureSize);
    index += uSignatureSize;

    *suppdata_len = index;

    // fill in length
    encodedLength = *suppdata_len - 3;
    suppdata[1]  = encodedLength >> 8 & 0xff;
    suppdata[2]  = encodedLength & 0xff;

    fprintf(stderr, "Generated Supp Data: len = %d\n", *suppdata_len);
    fflush(stderr);
    for (i=0; i<*suppdata_len; i++)
    {
        printf("0x%02x ", suppdata[i]);
        if (i%8 == 7)
        {
            printf ("\n");
        }
    }
    fprintf(stderr, "\n");
    fflush(stderr);
    return 0;
}

int validate_dtcp_suppdata(unsigned char *suppdata, unsigned short suppdata_len, int isServer, conn_rec *c)
{
    // Validate the suppdata by checking
    //    -- nonce is same sent by server
    //    -- signature of cert is valid
    //    -- cert itself is valid

    unsigned char *pStartOfSignedBytes = 0;
    unsigned int uNumSignedBytes = 0;
    unsigned char *pRemoteCert;
    unsigned int uRemoteCertSize = 0;
    unsigned char pSignature[40];
    unsigned int uSignatureSize = 40;
    unsigned int x509Size = 0;
    unsigned char * x509;
    unsigned char nonce[32];
    unsigned int index = 3;
    int i=0;
    int nReturnCode;

    fprintf(stderr, "validate_dtcp_suppdata - suppdata length %d\n", suppdata_len);
    fflush(stderr);
    if (isServer != 0)
    {
        memcpy (nonce, suppdata + index, 32);
        index += 32;

        // compare nonce to nonce sent previously
 //       stored_nonce = (unsigned char *)apr_table_get(c->notes, "DTCP_NONCE");

        if (!g_stored_nonce)
        {
            fprintf(stderr, "validate_dtcp_suppdata: validation failed: no cached nonce\n");
            fflush(stderr);
            return -1;
        } 
        for (i=0; i<32; i++)
        {
            if (g_stored_nonce[i] != nonce[i])
            {
                fprintf(stderr, "validate_dtcp_suppdata: validation failed: invalid nonce: %d, %x, %x\n", i, g_stored_nonce[i], nonce[i]);
                fflush(stderr);
                return -1;
            }
        }
    }
    else 
    {
        //skip nonce
        index += 32;
    }

    //next two bytes are dtcp cert length - always sent by client
    pStartOfSignedBytes = suppdata + index;
    uRemoteCertSize = (suppdata[index] << 8) | suppdata[index+1];
    index += 2;
    uNumSignedBytes = uRemoteCertSize + 2;

    fprintf(stderr, "dtcp cert - size %d\n", uRemoteCertSize);
    fflush(stderr);
    pRemoteCert = apr_pcalloc(c->pool, uRemoteCertSize);

    memcpy (pRemoteCert, suppdata + index, uRemoteCertSize);
    index += uRemoteCertSize;

    //if suppdata_len - index > signature size, x509 cert is present (x509 is optional from client)
    //suppdata is received before peer cert - check peer cert outside of the callback
    if ((suppdata_len - index) > uSignatureSize)
    {
        x509Size = (suppdata[index] << 8) | suppdata[index+1];
        index += 2;
        fprintf(stderr, "x509 - size %d\n", x509Size);
        fflush(stderr);
        x509 = apr_pcalloc(c->pool, x509Size);
        memcpy (x509, suppdata + index, x509Size);
        apr_table_setn(c->notes, "DTCP_X509", x509);
        char * result;
        result = apr_itoa(c->pool, x509Size);
        apr_table_setn(c->notes, "DTCP_X509_LENGTH", result);
        index += x509Size;

        uNumSignedBytes += 2 + x509Size;
    }

    memcpy (pSignature, suppdata + index, uSignatureSize);
    index += uSignatureSize;

    // validate signature
    nReturnCode =   DTCPIPAuth_VerifyData(pStartOfSignedBytes, uNumSignedBytes, pSignature,   
        pRemoteCert);
    fprintf(stderr, "DTCPIPAuth__VerifyData returned %d\n", nReturnCode);
    fflush(stderr);
    if (nReturnCode != 0)
    {
        fprintf(stderr, "validate_dtcp_suppdata: validation failed: invalid signature\n");
        fflush(stderr);
        return -1;
    }

    // validate cert
    nReturnCode =  DTCPIPAuth_VerifyRemoteCert(pRemoteCert);
    fprintf(stderr, "DTCPIPAuth__VerifyRemoteCert returned %d\n", nReturnCode);
    fflush(stderr);
    if (nReturnCode != 0)
    {
        fprintf(stderr, "validate_dtcp_suppdata: validation failed: invalid cert\n");
        fflush(stderr);
        return -1;
    }

    fprintf(stderr, "validate_dtcp_suppdata: validation successful\n");
    fflush(stderr);
    return 0;
}



