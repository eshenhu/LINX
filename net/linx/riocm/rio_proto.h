/*
 * Copyright (c) 2009-2010, Enea Software AB
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

#ifndef __RIO_PROTO_H__
#define __RIO_PROTO_H__

#define RIO_PROTOCOL    8911 /* 0x22cf */

/*
 * rio_sw_hlen: u16 dst_id, u8 dst_mbox, u8 pad, u16 protocol, u16 size
 * note that the first four bytes is only used to pass down info to driver
 * and is not part of the protocol itself.
 */
#define RIO_SW_HLEN 8
/* rio header length on media */
#define RIO_HLEN 4

#define RIO_SINGLE      0x01   
#define RIO_FRAG_START  0x02
#define RIO_FRAG        0x03
#define RIO_PATCH_START 0x04
#define RIO_PATCH       0x05
#define RIO_HEARTBEAT   0x06

/* MSB set (0x80) indicates that the type does not require a dst_cid */
#define RIO_CONN_REQ    0x81
#define RIO_CONN_ACK    0x82
#define RIO_CONN_RESET  0x83

/* Generic headers. */

/* subset of connect headers */
struct rio_gen_conn {
	uint8_t  type;
	uint8_t  generation;
	uint16_t mtu;
	uint16_t dst_port;
	uint16_t rsvd; /* used by the actual headers */
	uint16_t sender;
	uint16_t src_port;
}; /* 4 byte unaligned!! */

/* subset of all udata headers below */
struct rio_gen_udata {
	uint8_t  type;
	uint8_t  msgid;
	uint16_t seqno;
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
}; /* 4 byte unaligned */

/* connect headers */
struct rio_conn_req {
	uint8_t  type;
	uint8_t  generation;
	uint16_t mtu;
	uint16_t dst_port;
	uint8_t  rsvd;
	uint8_t  hb_tmo;
	uint16_t sender;
	uint16_t src_port;
};

struct rio_conn_ack {
	uint8_t  type;
	uint8_t  generation;
	uint16_t mtu_ack;
	uint16_t dst_port;
	uint8_t  generation_ack;
	uint8_t  hb_tmo_ack;
	uint16_t sender;
	uint16_t src_port;
	uint16_t my_cid;
};

struct rio_conn_reset {
	uint8_t  type;
	uint8_t  generation;
	uint16_t mtu;
	uint16_t dst_port;
	uint16_t rsvd;
	uint16_t sender;
	uint16_t src_port;
};

/* udata headers */
struct rio_single {
	uint8_t  type;
	uint8_t  msgid;
	uint16_t seqno;
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
	uint32_t src;
	uint32_t dst;
	uint32_t payl_size;
};

struct rio_frag_start {
	uint8_t  type;
	uint8_t  msgid;
	uint16_t seqno;
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
	uint32_t src;
	uint32_t dst;
	uint32_t payl_size;
};

struct rio_frag {
	uint8_t  type;
	uint8_t  msgid;
	uint16_t seqno;
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
};

struct rio_patch_start {
	uint8_t  type;
	uint8_t  msgid;
	uint16_t seqno;
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
	uint32_t src;
	uint32_t dst;
	uint32_t payl_size;
	uint16_t count_frag;
	uint16_t count_patch;
};

struct rio_patch {
	uint8_t  type;
	uint8_t  msgid;
	uint16_t seqno;
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
};

/* heartbeat has an exclusive header, but dst places is common with udata */
struct rio_heartbeat {
	uint8_t  type;
	uint8_t  pad;  /* not used */
	uint16_t rsvd; /* not used */
	uint16_t dst_port;
	uint16_t dst_cid;
	uint16_t sender;
	uint16_t src_port;
};

#define CONN_REQ_HSIZE    (sizeof(struct rio_conn_req))
#define CONN_ACK_HSIZE    (sizeof(struct rio_conn_ack))
#define CONN_RESET_HSIZE  (sizeof(struct rio_conn_reset))
#define SINGLE_HSIZE      (sizeof(struct rio_single))
#define FRAG_START_HSIZE  (sizeof(struct rio_frag_start))
#define FRAG_HSIZE        (sizeof(struct rio_frag))
#define PATCH_START_HSIZE (sizeof(struct rio_patch_start))
#define PATCH_HSIZE       (sizeof(struct rio_patch))
#define HEARTBEAT_HSIZE   (sizeof(struct rio_heartbeat))

#define MAX_HDR_SIZE (PATCH_START_HSIZE)

#endif
