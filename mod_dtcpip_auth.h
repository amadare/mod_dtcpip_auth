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

#ifndef __H_MOD_DTCPIP_AUTH
#define __H_MOD_DTCPIP_AUTH

#include "dtcpip_auth.h"
static int validate_dtcp_suppdata(unsigned char *suppdata, unsigned short suppdata_len, int isServer, conn_rec *c);
static int format_dtcp_suppdata(unsigned char *suppdata, unsigned short *suppdata_len, 
    unsigned char *pServerSuppdata, int isServer, int sendCert, X509 *cert, conn_rec *c);

#endif // __H_MOD_DTCPIP_AUTH
