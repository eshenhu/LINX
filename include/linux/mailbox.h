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
#ifndef MAILBOX_H
#define MAILBOX_H

#include <linux/types.h>

struct mb;

struct mb_vec {
        const void *base;
        size_t len;
        int type;
};

#define MB_EARG    -1
#define MB_EBUSY   -2

/**
 * @function mb_cb
 *
 * @brief Client callback function. Called when there is data to
 * receive for this mail box.
 *
 * @long NOTE: this interface does not guarantee that the callback will be
 * called exactly once for each time a slot has been made ready, there
 * may be more than one slot available when the callback is called.
 *
 * @input mb pointer to mailbox object
 *
 * @input data pointer to client's private data (as specified when
 * registering the client).
 *
 */
typedef void (*mb_cb)(struct mb *mb, void *data);

/**
 * @function mb_start_service
 *
 * @brief Global init of mailboxes.
 *
 * @long Should be called once at startup. Starts necessary processess
 * and initializes shared memory etc.
 *
 * @input shm_base base address of shared memory
 * @input shm_size size of shared memory
 * @input no_mbs number of mailboxes to set up
 * @input side which "side" of the shared memory this is. Should be 0 on 
 * one side and 1 on the other.
 *
 */
void mb_start_service(void *shm_base, int shm_size, int no_mbs, int side);


/**
 * @function mb_init
 *
 * @brief Initialize mail box flib.
 *
 * @long Must be called at least once from each load module that uses
 * mail boxes, before calling any other mail box function. NOTE that
 * if mb_start_service() has not run before calling mb_init(), this
 * call will hang until mb_start_service() has been called.
 *
 */
extern void mb_init(void);

/**
 * @function mb_register_rx_client
 *
 * @brief Register RX client.
 *
 * @long Sets up a mailbox area for the client to use for
 * communication.
 *
 * @input id Identifies which mail box should be used.
 * @input slot_size Size of the slots used. This is the maximum amount
 * of data that can be received in one slot.
 * @input num_slots Number of slots.
 * @input cb Callback function. This is the function that will be
 * called when there is data to receive in the mailbox.
 * @input data Pointer to client private data that will be passed in
 * call to callback function.
 *
 * @return Pointer to mailbox object on success, NULL on failure.
 *
 */

extern struct mb *mb_register_rx_client(int id, size_t slot_size,
                                        int num_slots, mb_cb cb, 
                                        void *data);

/**
 * @function mb_register_tx_client
 *
 * @brief Register TX client.
 *
 * @long Sets up a mailbox area for the client to use for
 * communication.
 *
 * @input id Identifies which mail box should be used.
 * @input slot_size Size of the slots used. This is the maximum amount
 * of data that can be received in one slot.
 * @input num_slots Number of slots.
 *
 * @return Pointer to mailbox object on success, NULL on failure.
 *
 * Example:
 *
 * OSE side:
 *   ...
 *   mb_init();
 *   tx_mb = mb_register_tx_client(7, 128, 32);
 *   rx_mb = mb_register_rx_client(7, 16, 256, ose_callback, &my_data);
 *   ...
 *
 * Linux side:
 *   ...
 *   mb_init();
 *   tx_mb = mb_register_tx_client(7, 16, 256);
 *   rx_mb = mb_register_rx_client(7, 128, 32, linux_callback, &data);
 *   ...
 *
 */
extern struct mb *mb_register_tx_client(int id, size_t slot_size,
                                        int num_slots);

/**
 * @function mb_unregister_rx_client
 *
 * @brief Unregister a client.
 *
 * @long After the call returns, it is guaranteed that the client's
 * callback function will not be called.
 *
 * @input id The client id.
 *
 * @return 0 on success, <0 on failure (attempt to delete a mailbox
 * which is not in use).
 *
 */
extern int mb_unregister_rx_client(int id);

/**
 * @function mb_unregister_tx_client
 *
 * @brief Unregister a client.
 *
 * @long After the call returns, the client is no longer allowed to
 * send messages.
 *
 * @input id The client id.
 *
 * @return 0 on success, <0 on failure (attempt to delete a mailbox
 * which is not in use).
 *
 */
extern int mb_unregister_tx_client(int id);

/**
 * @function mb_set_vec
 *
 * @brief Prepare a vector for later tranmisssion wich mb_xmit_vec()
 *
 * @long This can be used to send data located in several different
 * places without having to copy the data first.
 *
 * @input vec Pointer to mb_vec object to be initialized
 * @input data Pointer to data to be transmitted
 * @input size Size of data
 * @input is_kernel_mem Not used in OSE
 *
 * @return 0
 *
 */
extern int mb_set_vec(struct mb_vec *vec, const void *data, size_t size, 
                      int is_kernel_mem);

/**
 * @function mb_xmit_vec
 *
 * @brief Transmit data
 *
 * @input vec Array of mb_vec objects (previously set up with
 * mb_set_vec()) 
 * @input count Number of elements in vec
 *
 * @return 0 on success, <0 on failure (i.e. mailbox is full)
 *
 */
extern int mb_xmit_vec(struct mb *mb, const struct mb_vec *vec, 
                       size_t count);

/**
 * @function mb_xmit
 *
 * @brief Transmit data
 *
 * @long
 *
 * @input data Pointer to data to transmit
 * @input size Number of bytes to transmit
 * @input is_kernel_mem Not used in OSE
 *
 * @return 0 on success, <0 on failure (i.e. mailbox is full)
 *
 */
extern int mb_xmit(struct mb *mb, const void *data, size_t size, 
                   int is_kernel_mem);

/**
 * @function mb_get_slot
 *
 * @brief Get address of next incoming data.
 *
 * @long This should normally be called from the client's callback
 * function.
 *
 * @input mb The RX mail box.
 *
 * @return Address of user data if there is any, NULL otherwise.
 *
 */
extern void *mb_get_slot(struct mb *mb);

/**
 * @function mb_done
 *
 * @brief Tell mailbox that the slot can be reused.
 *
 * @long This should be called after the client has copied the data
 * from a slot received through the mb_get_slot() call.
 *
 * @input mb RX mail box
 * @input slot The slot previously received through mb_get_slot()
 *
 */
extern void mb_done(struct mb *mb, void *slot);

#endif
