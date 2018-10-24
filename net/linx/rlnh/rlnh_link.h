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

/*
 * This file defines the interface between RLNH and a CM (connection manager).
 * The interface consists of two functions sets, up-calls and down-calls.
 * The up-calls are defined by struct RlnhLinkUCIF. They are implemented in
 * RLNH and are used by the CM. The down-calls are defined by struct RlnhLinkIF.
 * They are implemented in the CM and are used by RLNH.
 *
 * The following sequence shows the "normal" call sequence, from link create to
 * link destroy. Once the link is connected, messages are transmitted and
 * delivered over the link.
 *
 * RLNH
 *      init() connect()     transmit()...  disconnect()  finalize()
 *        |       |              |              |             |
 * ---------------------------------------------------------------------------->
 *                      |            |                |                     time
 *                  connected()  deliver()...   disconnected()
 * CM
 *
 * If an error is detected by RLNH, the link is disconnected and re-connected.
 * Notice that the CM responds with disconnected() when RLNH calls disconnect().
 *
 * RLNH
 *      connect()   error detected   disconnect()   connect()
 *         |              |               |            |    
 * ---------------------------------------------------------------------------->
 *                                              |               |           time
 *                                        disconnected()    connected()
 * CM
 *
 * If an error is detected by the CM after connect(), two different scenarios
 * are possible:
 *
 * 1. Before connected(), the CM should keep trying to connect to its peer or
 * sit tight until disconnect().
 *
 * RLNH
 *      connect()                            disconnect()
 *         |                                      |
 * ---------------------------------------------------------------------------->
 *                 |                                      |                 time
 *           error detected...                       disconnected()
 * CM
 *
 * 2. After connected(), the CM must call disconnected().
 *
 * RLNH
 *      connect()                                    connect()
 *         |                                            |
 * ---------------------------------------------------------------------------->
 *               |               |              |              |            time
 *           connected()  error detected  disconnected()   connected()
 * CM
 *
 * The implementation of these functions (or callbacks) may vary, in some
 * implementations the tasks are carried out directly in the functions and in
 * others the tasks are deferred to e.g. a workqueue. A couple of "race"
 * situation can occur.
 *
 * After disconnect(), RLNH must tolerate connected() and deliver() until
 * disconnected().
 *
 * RLNH
 *      connect()  disconnect()                                 connect()
 *         |            |       X            X                     |
 * ---------------------------------------------------------------------------->
 *                              |            |               |              time
 *                          connected()  deliver()...  disconnected()
 * CM
 * 
 * If the CM detects an error after connected(), it calls disconnected(). In
 * this state, it must tolerate a disconnect(). Also transmit() must also be
 * tolerated, see text below.
 *
 * RLNH
 *      connect()                                    disconnect()
 *         |                                              |
 * ---------------------------------------------------------------------------->
 *               |               |              |         X                 time
 *           connected()  error detected  disconnected()
 * CM
 *
 * In addition to these sequences...
 *
 * The CM must make sure that deliver() for a connection (i.e. same co
 * parameter) does not preempt each other.
 * 
 * The CM must make sure that deliver() is not called any more and that all
 * on-going deliver() have returned before calling disconnected().
 *
 * The CM must make sure that deliver() is not called until connected() has
 * returned.
 *
 * The CM must make sure that it can handle transmit() before calling
 * connected(), then it must tolerate transmit() until the next connect().
 *
 * The CM must make sure that connected() and disconnected() for a connection
 * (i.e. same co parameter) does not preempt each other.
 *
 * The CM must make sure that it can handle finalize() before calling
 * disconnected().
 *
 * The CM may use alloc(), free() and error() until the CM code does return in
 * finalize().
 */
#ifndef __RLNH_LINK_H__
#define __RLNH_LINK_H__

struct RlnhLinkObj;

#define RLNH_LINK_UC_IF_VERSION 5

struct RlnhLinkUCIF {
	uint32_t if_version;
        int (*deliver)(void *rlnh_obj, uint32_t buffer_type, uint32_t src_addr,
                       uint32_t dst_addr, uint32_t size, void *data);
	void *(*alloc)(void *rlnh_obj, uint32_t buffer_type, uint32_t size);
	void (*free)(void *rlnh_obj, uint32_t buffer_type, void *ptr);
	void (*error)(void *rlnh_obj, void *error_info);
	void (*connected)(void *rlnh_obj);
	void (*disconnected)(void *rlnh_obj);
};

#define RLNH_LINK_IF_VERSION 6

struct RlnhLinkIF {
	uint32_t if_version;
	void (*init)(struct RlnhLinkObj *co, void *rlnh_obj,
                     struct RlnhLinkUCIF *cb);
	void (*finalize)(struct RlnhLinkObj *co);
	void (*connect)(struct RlnhLinkObj *co);
	void (*disconnect)(struct RlnhLinkObj *co);
	int (*transmit)(struct RlnhLinkObj *co, uint32_t buffer_type,
                        uint32_t src_addr, uint32_t dst_addr, uint32_t size,
                        void *data);
};

#endif
