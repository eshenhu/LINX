/*
 * Copyright (c) 2006-2007, Enea Software AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * Neither the name of Enea Software AB nor the names of its
 * contributors may be used to endorse or promote products derived from this
 * software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/****************************************************************************
 * The RLNH-to-RLNH control protocol
 ****************************************************************************
 */

#ifndef __RLNH_PROTO_H__
#define __RLNH_PROTO_H__

#define RLNH_PROTOCOL_VERSION   2

#define RLNH_PROTOCOL_SUPPORTED       0
#define RLNH_PROTOCOL_NOT_SUPPORTED   1

/* The link address of the linkhandler. */
#define RLNH_LINKADDR       0

/* --- RLNH Main hdr - all messages must start with this header 
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  Reserved                     |     Type      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

static inline uint32_t type(uint32_t h)
{
	return h & 0xff;
}

static inline uint32_t set_type(uint32_t h, uint32_t n)
{
	return h |= n & 0xff;
}

/* Request an RLNH_PUBLISH from the remote side
   regarding "name" */
#define RLNH_QUERY_NAME     (1)
struct RlnhQueryName {
	uint32_t main_hdr;
	uint32_t linkaddr;
	char name[1];
};

/* Tell other side that the name "name" has the link
   address "linkaddr". */
#define RLNH_PUBLISH        (2)
struct RlnhPublish {
	uint32_t main_hdr;
	uint32_t linkaddr;
	char name[1];
};

/* Tell the other side that the link address "linkaddr"
   has been unpublished. */
#define RLNH_UNPUBLISH      (3)
struct RlnhUnpublish {
	uint32_t main_hdr;
	uint32_t linkaddr;
};

/* Tell the other side that it is now ok to reuse
   the link address "linkaddr. */
#define RLNH_UNPUBLISH_ACK  (4)
struct RlnhUnpublishAck {
	uint32_t main_hdr;
	uint32_t linkaddr;
};

#define RLNH_INIT           (5)
struct RlnhInit {
	uint32_t main_hdr;
	uint32_t version;
};

#define RLNH_INIT_REPLY     (6)
struct RlnhInitReply {
	uint32_t main_hdr;
	uint32_t status;
	char features[1];
};

#define RLNH_PUBLISH_PEER   (7)
struct RlnhPublishPeer {
	uint32_t main_hdr;
	uint32_t linkaddr;
	uint32_t peer_linkaddr;
};

#endif
