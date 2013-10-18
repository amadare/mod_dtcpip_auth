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

#ifndef _H_CVP2_DTCP__
#define _H_CVP2_DTCP__

#define CVP_DTCP_SUCCESS		             0
#define CVP_DTCP_FAILURE                    -1
#define CVP_DTCP_INSUFFICIENT_MEM_ERROR     -2
// other error codes to be added as needed


int CVP2_DTCPIP_GetLocalCert (
    unsigned char *pLocalCert, 
    unsigned int *pLocalCertSize);

int CVP2_DTCPIP_VerifyRemoteCert( 
    unsigned char *pRemoteCert );
	
int CVP2_DTCPIP_SignData( 
    unsigned char *pData, 
    unsigned int nDataSz, 
    unsigned char *pSignature,   
    unsigned int *pnSignatureSz);

int CVP2_DTCPIP_VerifyData( 
    unsigned char *pData, 
    unsigned int nDataSz, 
    unsigned char *pSignature, 
    unsigned char *pRemoteCert );

int CVP2_DTCPIP_Init(
    char *pCertStorageDir);


#endif // _H_CVP2_DTCP__
