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

#ifndef __H_MOD_DTCPIP_AUTH
#define __H_MOD_DTCPIP_AUTH

#include "dtcpip_auth.h"
static int validate_dtcp_suppdata(const unsigned char *suppdata, unsigned short suppdata_len, conn_rec *c);
static int format_dtcp_suppdata(const unsigned char **suppdata, unsigned short *suppdata_len, X509 *cert,
                                int send_certs, conn_rec *c);
static int propagate_validation (request_rec *r);
static void mod_dtcpip_auth_register_hooks (apr_pool_t *p);

const char* set_library_path(cmd_parms* cmd, void *cfg, const char* arg);
const char* set_key_dir(cmd_parms* cmd, void *cfg, const char* arg);
const char* set_send_certs(cmd_parms* cmd, void *cfg, int flag);
const char* set_require_reneg(cmd_parms* cmd, void *cfg, int flag);
const char* set_enable_dtcp_encryption(cmd_parms *cmd, void *cfg, int flag);
const char* set_dtcp_encryption_port(cmd_parms *cmd, void *cfg, const char* arg);

#endif // __H_MOD_DTCPIP_AUTH
