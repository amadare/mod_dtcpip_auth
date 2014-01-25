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

#include "s_dtcp_interface.h"

#include <stdlib.h>
#include <stdio.h>


#if defined ( _WIN32) || defined (__CYGWIN__)

#include <windows.h>

typedef int (_cdecl *DTCPCmnInit_PROC) (char *);
typedef int (__cdecl *DTCPGetLocalCert_PROC)(unsigned char *, unsigned int *);
typedef int (__cdecl *DTCPVerifyRemoteCert_PROC)(unsigned char *);
typedef int (__cdecl *DTCPSignData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned int*);
typedef int (__cdecl *DTCPVerifyData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned char*);
typedef int (__cdecl *DTCPInit_PROC)(char *);
// initializes the source -- the dtcp_port is the listener port to use for AKE
typedef int (__cdecl *DTCPSrcInit_PROC)(unsigned short dtcp_port);

// Opens a source session. I cant recall how the is_audio_only flag is used -- I need tocheck,
// but it can be set to 0 (false) for now. session_handle is returned and is used to idetify
// this session in subsequent DTCPIP source calls.
typedef int (__cdecl *DTCPSrcOpen_PROC)(int* session_handle, int is_audio_only);

// Encrypts a piece of cleartext data in a single PCP packet.
// The cci parameter is the cci for the data stream; cci values are:
// 0x00 extEmiCopyFree
// 0x20 extEmiCopyFreeEpnAsserted
// 0x01 extEmiNoMoreCopies
// 0x02 extEmiCopyOneGenFormatCog
// 0x03 extEmiCopyNever
//
typedef int (__cdecl *DTCPSrcAllocEncrypt_PROC)(int session_handle, unsigned char cci,
char* cleartext_data, unsigned int cleartext_size,
char** encrypted_data,unsigned int* encrypted_size);

// frees the encrypted data buffer returned by dtcpip_src_alloc_encrypt
typedef int (__cdecl *DTCPSrcFree_PROC)(char* encrypted_data);

// closes a source session and frees resources for that session
typedef int (__cdecl *DTCPSrcClose_PROC)(int session_handle);
#elif __linux__

#include <dlfcn.h>

typedef int (*DTCPCmnInit_PROC)(char *);
typedef int (*DTCPGetLocalCert_PROC)(unsigned char *, unsigned int *);
typedef int (*DTCPVerifyRemoteCert_PROC)(unsigned char *);
typedef int (*DTCPSignData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned int*);
typedef int (*DTCPVerifyData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned char*);
typedef int (*DTCPInit_PROC)(char *);

// initializes the source -- the dtcp_port is the listener port to use for AKE
typedef int (*DTCPSrcInit_PROC)(unsigned short dtcp_port);

// Opens a source session. I cant recall how the is_audio_only flag is used -- I need tocheck,
// but it can be set to 0 (false) for now. session_handle is returned and is used to idetify
// this session in subsequent DTCPIP source calls.
typedef int (*DTCPSrcOpen_PROC)(int* session_handle, int is_audio_only);

// Encrypts a piece of cleartext data in a single PCP packet.
// The cci parameter is the cci for the data stream; cci values are:
// 0x00 extEmiCopyFree
// 0x20 extEmiCopyFreeEpnAsserted
// 0x01 extEmiNoMoreCopies
// 0x02 extEmiCopyOneGenFormatCog
// 0x03 extEmiCopyNever
//
typedef int (*DTCPSrcAllocEncrypt_PROC)(int session_handle, unsigned char cci,
char* cleartext_data, unsigned int cleartext_size,
char** encrypted_data,unsigned int* encrypted_size);

// frees the encrypted data buffer returned by dtcpip_src_alloc_encrypt
typedef int (*DTCPSrcFree_PROC)(char* encrypted_data);

// closes a source session and frees resources for that session
typedef int (*DTCPSrcClose_PROC)(int session_handle);
#endif

DTCPCmnInit_PROC            hDTCPCmnInit            = NULL;
DTCPGetLocalCert_PROC       hDTCPGetLocalCert       = NULL;
DTCPVerifyRemoteCert_PROC   hDTCPVerifyRemoteCert   = NULL;
DTCPSignData_PROC           hDTCPSignData           = NULL;
DTCPVerifyData_PROC         hDTCPVerifyData         = NULL;
DTCPInit_PROC               hDTCPInit               = NULL;

DTCPSrcInit_PROC            hDTCPSrcInit            = NULL;
DTCPSrcOpen_PROC            hDTCPSrcOpen            = NULL;
DTCPSrcAllocEncrypt_PROC    hDTCPSrcAllocEncrypt    = NULL;
DTCPSrcFree_PROC            hDTCPSrcFree            = NULL;
DTCPSrcClose_PROC           hDTCPSrcClose           = NULL;

static int g_inited = 0;


#ifdef __linux__
int initDTCP(char *dllPath, char* keyStorageDir)
{
    int nReturnCode = 0;
    void * hModule = NULL;
    char *checkRet = (char *) 0;

    fprintf (stderr, "initDCP: dllPath = %s\n", dllPath);
    fprintf (stderr, "initDCP: keyStorageDir = %s\n", keyStorageDir);
    fflush(stderr);

    hModule = dlopen(dllPath, RTLD_LAZY);
    if (NULL == hModule)
    {
        fprintf (stderr, "initDCP returning -100\n");
        fprintf (stderr, "dlerror = %s\n", dlerror());
 	fflush(stderr);
        return -100;
    }


    /*
     * Per Linux Manpage
     * 1. Clear any extant errors
     * 2. Search for the symbol (NULL is legitimate return value)
     * 3. Check for resulting error
     */
    (void) dlerror();
    hDTCPGetLocalCert = (DTCPGetLocalCert_PROC) dlsym(hModule, "CVP2_DTCPIP_GetLocalCert");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPGetLocalCert)
    {
        fprintf (stderr, "initDCP returning -101\n");
        fprintf (stderr, "dlerror = %s\n", dlerror());
	fflush(stderr);
        return -101;
    }

    (void) dlerror();
    hDTCPVerifyRemoteCert = (DTCPVerifyRemoteCert_PROC) dlsym(hModule, "CVP2_DTCPIP_VerifyRemoteCert");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPVerifyRemoteCert)
    {
        fprintf (stderr, "initDCP returning -102\n");
	fflush(stderr);
        return -102;
    }

    (void) dlerror();
    hDTCPSignData =(DTCPSignData_PROC) dlsym(hModule, "CVP2_DTCPIP_SignData");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPSignData)
    {
        fprintf (stderr, "initDCP returning -103\n");
	fflush(stderr);
        return -103;
    }

    (void) dlerror();
    hDTCPVerifyData = (DTCPVerifyData_PROC) dlsym(hModule, "CVP2_DTCPIP_VerifyData");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPVerifyData)
    {
        fprintf (stderr, "initDCP returning -104\n");
	fflush(stderr);
        return -104;
    }

    (void) dlerror();
    hDTCPInit = (DTCPInit_PROC) dlsym(hModule, "CVP2_DTCPIP_Init");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPInit)
    {
        fprintf (stderr, "initDCP returning -105\n");
	fflush(stderr);
        return -105;
    }

    (void) dlerror();
    hDTCPSrcInit = (DTCPSrcInit_PROC) dlsym(hModule, "dtcpip_src_init");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPSrcInit)
    {
        fprintf (stderr, "initDCP returning -106\n");
    fflush(stderr);
        return -106;
    }

    (void) dlerror();
    hDTCPSrcOpen = (DTCPSrcOpen_PROC) dlsym(hModule, "dtcpip_src_open");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPSrcOpen)
    {
        fprintf (stderr, "initDCP returning -107\n");
    fflush(stderr);
        return -107;
    }

    (void) dlerror();
    hDTCPSrcAllocEncrypt = (DTCPSrcAllocEncrypt_PROC) dlsym(hModule, "dtcpip_src_alloc_encrypt");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPSrcAllocEncrypt)
    {
        fprintf (stderr, "initDCP returning -108\n");
    fflush(stderr);
        return -108;
    }

    (void) dlerror();
    hDTCPSrcFree = (DTCPSrcFree_PROC) dlsym(hModule, "dtcpip_src_free");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPSrcFree)
    {
        fprintf (stderr, "initDCP returning -109\n");
    fflush(stderr);
        return -109;
    }

    (void) dlerror();
    hDTCPSrcClose = (DTCPSrcClose_PROC) dlsym(hModule, "dtcpip_src_close");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPSrcClose)
    {
        fprintf (stderr, "initDCP returning -110\n");
    fflush(stderr);
        return -110;
    }

    (void) dlerror();
    hDTCPCmnInit = (DTCPCmnInit_PROC) dlsym(hModule, "dtcpip_cmn_init");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == hDTCPCmnInit)
    {
        fprintf (stderr, "initDCP returning -111\n");
        fprintf (stderr, "dlerror = %s\n", dlerror());
    fflush(stderr);
        return -111;
    }

    nReturnCode = hDTCPCmnInit (keyStorageDir);
    fprintf (stderr, "hDTCPCmnInit called with %s - returned: %d\n", keyStorageDir, nReturnCode);
    fflush(stderr);

    if (nReturnCode == 0)
    {
        g_inited = 1;
    }

//    nReturnCode = hDTCPInit (keyStorageDir);
//    fprintf (stderr, "hDTCPInit called with %s - returned: %d\n", keyStorageDir, nReturnCode);
//    fflush(stderr);

//    if (nReturnCode == 0)
//    {
//        g_inited = 1;
//    }

    return nReturnCode;
}
#endif


#if defined ( _WIN32) || defined (__CYGWIN__)
int initDTCP(char *dllPath, char* keyStorageDir)
{
    int nReturnCode = 0;

    HINSTANCE hDll = LoadLibrary(dllPath);
    if (NULL == hDll)
    {
        fprintf (stderr, "initDCP returning -100\n");
	fflush(stderr);
        return -100;
    }

    hDTCPGetLocalCert = (DTCPGetLocalCert_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_GetLocalCert");
    if (NULL == hDTCPGetLocalCert)
    {
        fprintf (stderr, "initDCP returning -101\n");
	fflush(stderr);
        return -101;
    }

    hDTCPVerifyRemoteCert = (DTCPVerifyRemoteCert_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_VerifyRemoteCert");
    if (NULL == hDTCPVerifyRemoteCert)
    {
        fprintf (stderr, "initDCP returning -102\n");
	fflush(stderr);
        return -102;
    }

    hDTCPSignData = (DTCPSignData_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_SignData");
    if (NULL == hDTCPSignData)
    {
        fprintf (stderr, "initDCP returning -103\n");
	fflush(stderr);
        return -103;
    }

    hDTCPVerifyData = (DTCPVerifyData_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_VerifyData");
    if (NULL == hDTCPVerifyData)
    {
        fprintf (stderr, "initDCP returning -104\n");
	fflush(stderr);
        return -104;
    }

    hDTCPInit = (DTCPInit_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_Init");
    if (NULL == hDTCPInit)
    {
        fprintf (stderr, "initDCP returning -105\n");
	fflush(stderr);
        return -105;
    }

    hDTCPSrcInit = (DTCPSrcInit_PROC) GetProcAddress(hDll, "dtcpip_src_init");
    if (NULL == hDTCPSrcInit)
    {
        fprintf (stderr, "initDCP returning -106\n");
    fflush(stderr);
        return -106;
    }

    hDTCPSrcOpen = (DTCPSrcOpen_PROC) GetProcAddress(hDll, "dtcpip_src_open");
    if (NULL == hDTCPSrcOpen)
    {
        fprintf (stderr, "initDCP returning -107\n");
    fflush(stderr);
        return -107;
    }

    hDTCPSrcAllocEncrypt = (DTCPSrcAllocEncrypt_PROC) GetProcAddress(hDll, "dtcpip_src_alloc_encrypt");
    if (NULL == hDTCPSrcAllocEncrypt)
    {
        fprintf (stderr, "initDCP returning -108\n");
    fflush(stderr);
        return -108;
    }

    hDTCPSrcFree = (DTCPSrcFree_PROC) GetProcAddress(hDll, "dtcpip_src_free");
    if (NULL == hDTCPSrcFree)
    {
        fprintf (stderr, "initDCP returning -109\n");
    fflush(stderr);
        return -109;
    }

    hDTCPSrcClose = (DTCPSrcClose_PROC) GetProcAddress(hDll, "dtcpip_src_close");
    if (NULL == hDTCPSrcClose)
    {
        fprintf (stderr, "initDCP returning -110\n");
    fflush(stderr);
        return -110;
    }

    hDTCPCmnInit = (DTCPCmnInit_PROC) GetProcAddress(hDll, "dtcpip_cmn_init");
    if (NULL == hDTCPCmnInit)
    {
        fprintf (stderr, "initDCP returning -111\n");
    fflush(stderr);
        return -111;
    }

    nReturnCode = hDTCPCmnInit (keyStorageDir);

    if (nReturnCode == 0)
    {
        fprintf (stderr, "hDTCPCmnInit successful\n");
    fflush(stderr);
    g_inited = 1;
    }

//    nReturnCode = hDTCPInit (keyStorageDir);

//    if (nReturnCode == 0)
//    {
//        fprintf (stderr, "hDTCPInit successful\n");
//    fflush(stderr);
//    g_inited = 1;
//    }


    return nReturnCode;
}
#endif

int DTCPIPAuth_GetLocalCert (
    unsigned char *pLocalCert, 
    unsigned int *pLocalCertSize)
{
    int nReturnCode = 0;

    if (g_inited == 0)
    {
    fprintf (stderr, "DTCPIPAuth_GetLocalCert: DTCP not inited, returning -1\n");
	fflush (stderr);
        return -1;
    }

    if (NULL == hDTCPGetLocalCert)
    {
        fprintf (stderr, "DTCPIPAuth_GetLocalCert returning -101\n");
	fflush (stderr);
        return -101;
    }

    nReturnCode = hDTCPGetLocalCert (pLocalCert, pLocalCertSize);
    fprintf (stderr, "DTCPIPAuth_GetLocalCert returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}


int DTCPIPAuth_VerifyRemoteCert( 
    unsigned char* pRemoteCert )
{
    int nReturnCode = 0;

    if (g_inited == 0)
    {
    fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert: DTCP not inited, returning -1\n");
	fflush (stderr);
        return -1;
    }
    fprintf (stderr, "g_inited != 0\n");
    fflush (stderr);

    if (NULL == hDTCPVerifyRemoteCert)
    {
        fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert returning -102\n");
	fflush (stderr);
        return -102;
    }

    nReturnCode = hDTCPVerifyRemoteCert (pRemoteCert);
    fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

	
int DTCPIPAuth_SignData( 
    unsigned char* pData, 
    unsigned int nDataSz, 
    unsigned char* pSignature,   
    unsigned int *pnSignatureSz)
{
    int nReturnCode = 0;

    if (g_inited == 0)
    {
    fprintf (stderr, "DTCPIPAuth_SignData: DTCP not inited, returning -1\n");
	fflush (stderr);
        return -1;
    }

    if (NULL == hDTCPSignData)
    {
        printf ("DTCPIPAuth_SignData returning -103\n");
        fflush (stderr);
        return -103;
    }
    nReturnCode = hDTCPSignData (pData, nDataSz, pSignature, pnSignatureSz);
    fprintf (stderr, "DTCPIPAuth_SignData returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}


int DTCPIPAuth_VerifyData( 
    unsigned char* pData, 
    unsigned int nDataSz, 
    unsigned char* pSignature, 
    unsigned char* pRemoteCert )
{
    int nReturnCode = 0;

    if (g_inited == 0)
    {
    fprintf (stderr, "DTCPIPAuth_VerifyData: DTCP not inited, returning -1\n");
	fflush (stderr);
        return -1;
    }

    if (NULL == hDTCPVerifyData)
    {
        printf ("DTCPIPAuth_VerifyData returning -104\n");
        fflush (stderr);
        return -104;
    }
    nReturnCode = hDTCPVerifyData (pData, nDataSz, pSignature, pRemoteCert);
    fprintf (stderr, "DTCPIPAuth_VerifyData returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

int DTCPIPSrc_Init(
    unsigned short dtcp_port)
{
    int nReturnCode = 0;

    if (NULL == hDTCPSrcInit)
    {
        fprintf (stderr, "DTCPIPSrc_Init null - returning -106\n");
        return -106;
    }
    nReturnCode = hDTCPSrcInit (dtcp_port);
    fprintf (stderr, "DTCPIPSrc_Init returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

int DTCPIPSrc_Open (
    int* session_handle,
    int is_audio_only )
{
    int nReturnCode = 0;

    if (NULL == hDTCPSrcOpen)
    {
        fprintf (stderr, "DTCPIPSrc_Open returning -107\n");
        return -107;
    }
    nReturnCode = hDTCPSrcOpen (session_handle, is_audio_only);
    fprintf (stderr, "DTCPIPSrc_Open returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

int DTCPIPSrc_AllocEncrypt (
    int session_handle, unsigned char cci,
    char* cleartext_data, unsigned int cleartext_size,
    char** encrypted_data,unsigned int* encrypted_size )
{
    int nReturnCode = 0;

    if (NULL == hDTCPSrcAllocEncrypt)
    {
        fprintf (stderr, "DTCPIPSrc_AllocEncrypt returning -108\n");
        return -108;
    }
    nReturnCode = hDTCPSrcAllocEncrypt (session_handle, cci, cleartext_data, cleartext_size, encrypted_data, encrypted_size);
    fprintf (stderr, "DTCPIPSrc_AllocEncrypt returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

int DTCPIPSrc_Free (
    char* encrypted_data )
{
    int nReturnCode = 0;

    if (NULL == hDTCPSrcFree)
    {
        fprintf (stderr, "DTCPIPSrc_Free returning -109\n");
        return -109;
    }
    nReturnCode = hDTCPSrcFree (encrypted_data);
    fprintf (stderr, "DTCPIPSrc_Free returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

int DTCPIPSrc_Close (
    int session_handle )
{
    int nReturnCode = 0;

    if (NULL == hDTCPSrcClose)
    {
        fprintf (stderr, "DTCPIPSrc_Close returning -110\n");
        return -110;
    }
    nReturnCode = hDTCPSrcClose (session_handle);
    fprintf (stderr, "DTCPIPSrc_Close returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}
