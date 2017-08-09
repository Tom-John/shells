/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#include "spp.h"

/**F*********************************************
 *
 * send packet, fragmented if required
 *
 ************************************************/
int send_pkt (spp_ctx *c, void *buf, int buflen)
{
    int     len, sum, outlen=buflen;
    uint8_t *p=(uint8_t*)buf;
    
    // 1. wrap it up
    outlen = encrypt(&c->cc, buf, buflen, SPP_ENCRYPT);
        
    // 2. send it
    for (sum=0; sum<outlen; sum += len) {
      len = send (c->s, (char*)&p[sum], outlen - sum, 0);
      if (len <= 0) {
        return -1;
      }
    }
    return sum;
}

/**F*********************************************
 *
 * send data, encrypted if required
 *
 ************************************************/
int spp_send (spp_ctx *c, spp_buf *in)
{
    int len, outlen=in->len.w;

    // 1. send length (including MAC)
    in->len.w += SPP_MAC_LEN;
    len = send_pkt (c, in->len.b, sizeof(int));
    
    if (len>0) {
      // 2. send data
      len = send_pkt (c, in->data.b, outlen);
    }
    // 3. return OK if no error
    return (len <= 0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

/**F*********************************************
 *
 * receive packet, fragmented if required
 *
 ************************************************/
int recv_pkt (spp_ctx *c, void *buf, int buflen) 
{
    int      len, sum;
    uint8_t  *p=(uint8_t*)buf;

    // 1. receive
    for (sum=0; sum<buflen; sum += len) {
      len=recv (c->s, (char*)&p[sum], buflen - sum, 0);
      if (len <= 0) {
        return -1;
      }
    }
    // 2. unwrap
    return encrypt(&c->cc, buf, buflen, CRYPT_DECRYPT);
}

/**F*********************************************
 *
 * receive data, decrypt if required
 *
 ************************************************/
int spp_recv (spp_ctx *c, spp_buf *out)
{
    int len;

    // 1. receive the length first
    len=recv_pkt (c, &out->len.w, sizeof(spp_len));
    
    if (len>0) {
      // 2. receive the data
      len=recv_pkt (c, &out->data.b, out->len.buflen);
      if (len>0) {
        out->data.b[len] = 0;
        out->len.buflen  = len;
      }
    }
    // 3. return OK if no errors
    return (len <= 0) ? SPP_ERR_SCK : SPP_ERR_OK;
}

