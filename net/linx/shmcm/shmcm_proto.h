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

#ifndef __SHMCM_PROTO_H__
#define __SHMCM_PROTO_H__

#include <linux/types.h>

/*
 * Main header
 */
struct shmcm_mhdr {
        uint32_t type; /* Protocol indicator and/or packet type. */
        uint32_t size; /* Packet size. */
};

#define CON_PKT 1
#define UDATA_1_PKT 2
#define UDATA_2_PKT 3

/*
 * Connection header
 */
struct shmcm_chdr {
        uint32_t type;
        uint16_t cno; /* Connection generation number. */
        uint16_t spare;
};

#define CON_REQ 1 /* Request packet. */
#define CON_ACK 2 /* Request-ack packet. */
#define CON_RST 3 /* Reset packet. */
#define CON_ALV 4 /* Alive packet. */

/*
 * User data header
 *
 * Note: Shared memory is reliable, i.e. sent packets always arrives
 *       in the order at the receiving end.
 *
 * Data can be found immediately after the header (UDATA_PKT_1) or
 * at "address" addr (UDATA_PKT_2).
 *
 * sizeof(shmcm_mhdr) + sizeof(shmcm_uhdr) = 32 bytes
 */
struct shmcm_uhdr {
        uint16_t cno; /* Connection generation number. */
        uint16_t msgid; /* Identifies a fragmented signal. */

        uint32_t src; /* Signal sender. */
        uint32_t dst; /* Signal addressee. */
        uint32_t size; /* Signal size. */
        uint64_t addr; /* Implementation dependant "address". */
};

/*
 * Connection state machine
 *
 *   STATE_DISCONNECTED <--> STATE_CONNECTING ---> STATE_CONNECTED
 *           ^                                           |
 *           |                                           |
 *           +-------------------------------------------+
 *
 * STATE_DISCONNECTED, up-call disconnected has been called. Also used
 *                     as initial state.
 *
 * STATE_CONNECTING, down-call connect has been received.
 *
 * STATE_CONNECTED, up-call connected has been called.
 *
 * In words...
 *
 * In DISCONNECTED state, the CM sits tight until a connect
 * down-call is received from RLNH. Once it got the down-call, a CON_REQ
 * is sent to the peer and the state is changed to CONNECTING.
 *
 * The CM remains in this state until a CON_REQ or a CON_ACK is received
 * from the peer. If a CON_REQ is received, the CM sends a CON_ACK, calls
 * connected (up-call) and changes its state to CONNECTED. If a CON_ACK is
 * received, the CM calls connected (up-call) and changes its state to
 * CONNECTED.
 *
 * If CON_ACK is received in CONNECTED state, it is ignored. However,
 * reception of a CON_RST or CON_REQ results in a disconnected up-call and
 * the state is changed to DISCONNECTED.
 *
 * In CONNECTED state a CON_ALV must be sent periodically to inform
 * the peer that "I'm alive".
 *
 * A disconnect down-call from RLNH results in a disconnected up-call and
 * a state transition to DISCONNECTED. Unless the state is DISCONNECTED,
 * a CON_RST must be sent before calling disconnected.
 */
#define STATE_DISCONNECTED 1
#define STATE_CONNECTING 2
#define STATE_CONNECTED 3

#define ALIVES_PER_TMO 3
#define ALIVE_RESET_VALUE (2 + (ALIVES_PER_TMO - 1))

#endif
