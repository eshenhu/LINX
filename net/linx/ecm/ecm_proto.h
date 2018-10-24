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

#ifndef __ECM_PROTO_H__
#define __ECM_PROTO_H__

#define ECM_PROTOCOL 0x8911
#define ECM_PROTOCOL_VERSION 3
#define ECM_HIGHEST_CONNID 255 /* Connection id range: 1-255, 0 is reserved */

#define UDATA_HSIZE (HDR_MAIN_SIZE + HDR_ACK_SIZE + HDR_UDATA_SIZE)
#define FRAG_HSIZE (HDR_MAIN_SIZE + HDR_ACK_SIZE + HDR_UDATA_FRAG_SIZE)
#define ACK_HSIZE (HDR_MAIN_SIZE + HDR_ACK_SIZE)
#define NACK_HSIZE (HDR_MAIN_SIZE + HDR_ACK_SIZE + HDR_NACK_SIZE)
#define CONN_HSIZE (HDR_MAIN_SIZE + HDR_CONN_SIZE)

/* Definitions of protocol header types. */
#define HDR_MULTICORE_SIZE 4
#define HDR_MAIN  0x0
#define HDR_MAIN_SIZE 4
#define HDR_CONN  0x1
#define HW_ADDRESS_SIZE   6
/* HDR_CONN_SIZE is without feature negotiation */
/* #define HDR_CONN_SIZE(hw_size) (1 + ((((hw_size) << 1) + 3 ))) */
#define HDR_CONN_SIZE 4+(HW_ADDRESS_SIZE*2)
#define HDR_UDATA 0x2
#define HDR_UDATA_SIZE 12
#define HDR_UDATA_FRAG_SIZE 4
#define HDR_FRAG  0x3
#define HDR_ACK	  0x4
#define HDR_ACK_SIZE 4
#define HDR_NACK  0x5
#define HDR_NACK_SIZE 4
#define HDR_NONE  0xf

/* HDR_MAIN_SIZE+HDR_ACK_SIZE+HDR_UDATA_SIZE or HDR_MAIN_SIZE+HDR_CONN_SIZE(6)*/
#define MAX_HDR_SIZE 20

static inline void hton_unaligned(void *_h, uint32_t w, int offset)
{
	char *h = _h;
#ifdef RLNH_ALIGN_ANY
	uint32_t *w32 = (uint32_t *) (h + offset);
	w32[0] = htonl(w);
#else
	uint16_t *w16 = (uint16_t *) (h + offset);
	w16[0] = htons(w >> 16);
	w16[1] = htons(w & 0xffff);
#endif
}

static inline uint32_t ntoh_unaligned(void *_h, int offset)
{
	char *h = _h;
#ifdef RLNH_ALIGN_ANY
	uint32_t *w32 = (uint32_t *) (h + offset);
	return ntohl(w32[0]);
#else
	uint16_t *w16 = (uint16_t *) (h + offset);
	return (ntohs(w16[0]) << 16) | ntohs(w16[1]);
#endif
}

static inline uint32_t get_next(uint32_t h)
{
	return h >> 28;
}

static inline uint32_t set_next(uint32_t h, uint32_t n)
{
	return h |= n << 28;
}

/* Multicore header */
/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |   R   |  Dest Coreid  | Source Coreid |      R        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define MULTICORE_HDR_OFFSET 0

static inline int get_dst_coreid(uint32_t h)
{
	return h >> 16 & 0xFF;
}

static inline int set_dst_coreid(uint32_t h, int dst_coreid)
{
	return h |= dst_coreid << 16;
}

static inline int get_src_coreid(uint32_t h)
{
	return h >> 8 & 0xFF;
}

static inline int set_src_coreid(uint32_t h, int src_coreid)
{
	return h |= src_coreid << 8;
}

/* Main header */
/*
  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  | Ver | R |	Connection  |R|	       Packet size	  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define MAIN_HDR_OFFSET 0

static inline uint32_t get_ver(uint32_t h)
{
	return h >> 25 & 0x07;
}

static inline uint32_t set_ver(uint32_t h, int ver)
{
	return h |= ver << 25;
}

static inline uint32_t get_cid(uint32_t h)
{
	return h >> 15 & 0xff;
}

static inline uint32_t set_cid(uint32_t h, int cid)
{
	return h |= (cid & 0xff) << 15;
}

static inline uint32_t get_packet_size(uint32_t h)
{
	return h & 0x3fff;
}

static inline uint32_t set_packet_size(uint32_t h, int s)
{
	return h |= s & 0x3fff;
}

static inline int get_main_hdr_size(void)
{
	return HDR_MAIN_SIZE;
}

/* Reliable header */
/*
  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |R| Res.|	    Ackno	  |	    Seqno	  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define ACK_HDR_OFFSET HDR_MAIN_SIZE

static inline uint32_t get_request(uint32_t h)
{
	return h >> 27 & 0x01;
}

static inline uint32_t set_request(uint32_t h, uint16_t a)
{
	return h |= (a & 0x01) << 27;
}

static inline uint32_t get_ackno(uint32_t h)
{
	return (h >> 12) & 0xfff;
}

static inline uint32_t set_ackno(uint32_t h, uint16_t a)
{
	return h |= (0xfff & a) << 12;
}

static inline uint32_t get_seqno(uint32_t h)
{
	return h & 0xfff;
}

static inline uint32_t set_seqno(uint32_t h, uint16_t s)
{
	return h |= (s & 0xfff);
}

static inline int get_ack_hdr_size(void)
{
	return HDR_ACK_SIZE;
}

/*
 * User data / fragment header (w oob) => Version 3
 
  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |O|	 Reserved	  |M|	       Frag no            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Destination                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             Source                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  * User data / fragment header => Version 3
 
  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |	 Reserved	  |M|	       Frag no		  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                          Destination                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                             Source                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  * User data / fragment header => Version 2

  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |	 Reserved	  |M|	       Frag no		  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                           Reserved                            |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |		  Dst		  |		  Src		  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
  - fragments (not first fragment)

  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |	 Reserved	  |M|	       Frag no		  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define UDATA_HDR_OFFSET 8

/* Used in version 3 */
#define UDATA_HDR_DST_OFFSET 12
#define UDATA_HDR_SRC_OFFSET 16

/* Used in version 2 */
#define UDATA_HDR_ADDR_OFFSET 16

#define FRAG_HDR_OFFSET 8

static inline uint32_t get_oob(uint32_t h)
{
	return (h >> 27 ) & 1;
}

static inline uint32_t set_oob(uint32_t h, int o)
{
	return h |= (o << 27);
}

static inline uint32_t get_more(uint32_t h)
{
	return (h & 0x8000) >> 15;
}

static inline uint32_t set_more(uint32_t h, int m)
{
	return h |= (m << 15);
}

static inline uint32_t get_fragno(uint32_t h)
{
	return h & 0x7fff;
}

static inline uint32_t set_fragno(uint32_t h, int f)
{
	return h |= f;
}

/* Used in version 2 */
static inline uint32_t get_dst(uint32_t h)
{
	return h >> 16;
}

/* Used in version 2 */
static inline uint32_t set_dst(uint32_t h, uint16_t d)
{
	return h |= (d << 16);
}

/* Used in version 2 */
static inline uint32_t get_src(uint32_t h)
{
	return h & 0xffff;
}

/* Used in version 2 */
static inline uint32_t set_src(uint32_t h, uint16_t s)
{
	return h |= (s & 0xffff);
}

static inline int get_udata_hdr_size(uint32_t h)
{
	/* Frag no must be 0x7fff if not fragmented! */
	return get_fragno(h) == 0x7fff ? HDR_UDATA_SIZE : HDR_UDATA_FRAG_SIZE;
}

/* Nack header */
/*
  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  |  Res  |	Count	  |  Res  |	    Seqno	  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define NACK_HDR_OFFSET (HDR_MAIN_SIZE + HDR_ACK_SIZE)

static inline uint32_t get_count(uint32_t h)
{
	return h >> 16 & 0xff;
}

static inline uint32_t set_count(uint32_t h, uint8_t c)
{
	return h |= c << 16;
}

static inline uint32_t get_seqno_n(uint32_t h)
{
	return h & 0xfff;
}

static inline uint32_t set_seqno_n(uint32_t h, uint16_t s)
{
	return h |= (0xfff & s);
}

/* Connect header */
/*
  0		      1			  2		      3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Next  | Type  |Size |Winsize|    Reserved	  |Publish conn id|
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  :								  :
  :		 dst hw addr followed by src hw addr		  :
  :								  :
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  :                                                               :
  :         feature negotiation string (null terminated)          :
  :                                                               :
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define CONN_HDR_OFFSET HDR_MAIN_SIZE

/* Type field Macros */
#define CONN_RESET	 1
#define CONN_CONNECT	 2
#define CONN_CONNECT_ACK 3
#define CONN_ACK	 4
#define CONN_TMO        15 /* Note: this is not a CONN pkt, but it must be reserved. */

static inline uint32_t get_conn_type(uint32_t h)
{
	uint32_t type = ((h & 0x0f000000) >> 24);

	return (type & 0xf);
}

static inline uint32_t set_conn_type(uint32_t h, uint32_t t)
{
	return h |= t << 24;
}

static inline uint32_t set_connect_size(uint32_t h, int s)
{
	return h |= s << 21;
}

static inline uint32_t get_connect_size(uint32_t h)
{
	return h >> 21 & 0x7;
}

static inline uint32_t get_window_size(uint32_t h)
{
	return h >> 17 & 0xF;
}

static inline uint32_t set_window_size(uint32_t h, int s)
{
	return h |= s << 17;
}

static inline uint32_t get_publish_conn_id(uint32_t h)
{
	return h & 0xff;
}

static inline uint32_t set_publish_conn_id(uint32_t h, int publish_connection)
{
	return h |= (publish_connection & 0xff);
}

static inline uint8_t *set_dst_hw_addr(uint8_t * h, uint8_t * hw)
{
	memcpy(&h[8], hw, ETH_ALEN);
	return h;
}

static inline uint8_t *get_dst_hw_addr(uint8_t * h)
{
	return &h[8];
}
		       
static inline uint8_t *set_src_hw_addr(uint8_t * h, uint8_t * hw)
{
	memcpy(&h[ETH_ALEN + 8], hw, ETH_ALEN);
	return h;
}

static inline uint8_t *get_src_hw_addr(uint8_t * h)
{
	return &h[8 + ETH_ALEN];
}

static inline uint8_t *get_feat_str(uint8_t * h)
{
	return &h[2 * ETH_ALEN + 8];
}

static inline uint8_t *set_feat_str(uint8_t * h, uint8_t * str,
				    unsigned int len)
{
	memcpy(&h[2 * ETH_ALEN + 8], str, len);
	return h;
}

#endif
