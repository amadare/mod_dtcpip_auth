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

#include "s_dtcp_interface.h"

#include <stdlib.h>
#include <stdio.h>


#if defined ( _WIN32) || defined (__CYGWIN__)

#include <windows.h>

typedef int (__cdecl *DTCPGetLocalCert_PROC)(unsigned char *, unsigned int *);
typedef int (__cdecl *DTCPVerifyRemoteCert_PROC)(unsigned char *);
typedef int (__cdecl *DTCPSignData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned int*);
typedef int (__cdecl *DTCPVerifyData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned char*);
typedef int (__cdecl *DTCPInit_PROC)(char *);

#elif __linux__

#include <dlfcn.h>

typedef int (*DTCPGetLocalCert_PROC)(unsigned char *, unsigned int *);
typedef int (*DTCPVerifyRemoteCert_PROC)(unsigned char *);
typedef int (*DTCPSignData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned int*);
typedef int (*DTCPVerifyData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned char*);
typedef int (*DTCPInit_PROC)(char *);

#endif


DTCPGetLocalCert_PROC       hDTCPGetLocalCert       = NULL;
DTCPVerifyRemoteCert_PROC   hDTCPVerifyRemoteCert   = NULL;
DTCPSignData_PROC           hDTCPSignData           = NULL;
DTCPVerifyData_PROC         hDTCPVerifyData         = NULL;
DTCPInit_PROC               hDTCPInit               = NULL;


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

    nReturnCode = hDTCPInit (keyStorageDir);
    fprintf (stderr, "hDTCPInit returned: %d\n", nReturnCode);
    fflush(stderr);

    if (nReturnCode == 0)
    {
        fprintf (stderr, "initDCP successful\n");
	fflush(stderr);
        g_inited = 1;
    }

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

    nReturnCode = hDTCPInit (keyStorageDir);

    if (nReturnCode == 0)
    {
        fprintf (stderr, "initDCP successful\n");
	fflush(stderr);
        g_inited = 1;
    }

    return nReturnCode;
}
#endif



int DTCPIPAuth_GetLocalCert (
    unsigned char *pLocalCert, 
    unsigned int *pLocalCertSize)
{
    int nReturnCode = 0;
    fprintf (stderr, "Inside DTCPIPAuth_GetLocalCert\n");
    fflush (stderr);

    if (g_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_GetLocalCert: DTCP not inited, returning -1");
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

    fprintf (stderr, "Inside DTCPIPAuth_VerifyRemoteCert\n");
    fflush (stderr);

    if (g_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert: DTCP not inited, returning -1");
	fflush (stderr);
        return -1;
    }
	fprintf (stderr, "g_inited != 0");
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

    fprintf (stderr, "Inside DTCPIPAuth_SignData\n");
    fflush (stderr);

    if (g_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_SignData: DTCP not inited, returning -1");
	fflush (stderr);
        return -1;
    }

    if (NULL == hDTCPSignData)
    {
        printf ("DTCPIPAuth_SignData returning -103\n");
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

    fprintf (stderr, "Inside DTCPIPAuth_VerifyData\n");
    fflush (stderr);

    if (g_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_VerifyData: DTCP not inited, returning -1");
	fflush (stderr);
        return -1;
    }

    if (NULL == hDTCPVerifyData)
    {
        printf ("DTCPIPAuth_VerifyData returning -104\n");
        return -104;
    }
    nReturnCode = hDTCPVerifyData (pData, nDataSz, pSignature, pRemoteCert);
    fprintf (stderr, "DTCPIPAuth_VerifyData returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}


int DTCPIPAuth_Init(
    char * pCertStorageDir)
{
    int nReturnCode = 0;


    printf ("Inside DTCPIPAuth_Init\n");
    if (NULL == hDTCPInit)
    {
        printf ("DTCPIPAuth_Init returning -105\n");
        return -105;
    }
    nReturnCode = hDTCPInit (pCertStorageDir);
    printf ("DTCPIPAuth_Init returning %d\n", nReturnCode);

    return nReturnCode;
}


