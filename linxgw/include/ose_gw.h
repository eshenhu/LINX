/*
 * Copyright (c) 2009, Enea Software AB
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

/**
 * @public
 * @toc OSE_Gateway_Client:
 * @file ose_gw.h
 * 
 * @brief     OSE Gateway Client
 */ 


#ifndef _OSEGW_H
#define _OSEGW_H

#include <stdint.h>

/*
 ***********************************************************************
 * Basic types and definitions.
 ***********************************************************************
 */

/*
 * OSE standard types and definitions except all have the "OSEGW_"
 * prefix.
 */

/**
 * @type OSEGW_OSBOOLEAN 
 * @brief BOOLEAN type.   
 */

typedef unsigned char  OSEGW_OSBOOLEAN;


/** 
 * @type OSEGW_PROCESS   
 * @brief PROCESS type.   
 */

typedef uint32_t  OSEGW_PROCESS;


/** 
 * @type OSEGW_SIGSELECT 
 * @brief SIGSELECT type. 
 */

typedef uint32_t  OSEGW_SIGSELECT;


/** 
 * @type OSEGW_OSBUFSIZE 
 * @brief OSBUFSIZE type. 
 */

typedef uint32_t  OSEGW_OSBUFSIZE;


/** 
 * @type OSEGW_OSUSER    
 * @brief OSUSER type.    
 */

typedef uint32_t  OSEGW_OSUSER;


/** 
 * @type OSEGW_OSERRCODE 
 * @brief OSERRCODE type. 
 */

typedef unsigned long  OSEGW_OSERRCODE;


/** 
 * @type OSEGW_OSADDRESS 
 * @brief OSADDRESS type. 
 */

typedef uint32_t  OSEGW_OSADDRESS;


/** 
 * @type OSEGW_OSTIME    
 * @brief OSTIME type.    
 */

typedef uint32_t  OSEGW_OSTIME;


/** 
 * @type OSEGW_OSATTREF  
 * @brief OSATTREF type.  
 */

typedef uint32_t  OSEGW_OSATTREF;



#define OSEGW_NIL ((union OSEGW_SIGNAL *) 0)

union OSEGW_SIGNAL;                     /* Forward declaration. */

#define OSEGW_OS_ATTACH_SIG (252)       /* !-SIGNO(OSEGW_SIGSELECT)-! */

#define OSEGW_PING_TIMEOUT (1000) /* Time between pings (in milliseconds) */

/*
 * OSE Gateway specific definitions.
 */

struct OSEGW;                           /* Forward declaration. */

typedef int OSEGW_BOOLEAN;
#define OSEGW_FALSE 0
#define OSEGW_TRUE  1

/* This is the standard gateway broadcast address. */
#define OSEGW_STD_BRC_ADDR "udp://*:21768"

/*
 * These are the possible "blocking object" values returned by
 * osegw_get_blocking_object().
 */
#define OSEGW_BO_UNAVAILABLE 0
#define OSEGW_BO_SOCKET      1

/*
 ***********************************************************************
 * Error codes used as paramaters to error handlers.
 ***********************************************************************
 */

/**
 * @macro OSEGW_EOK
 * @brief
 *    This value is returned by osegw_get_error() to indicate that no
 *    error has occured.
 */

#define OSEGW_EOK               0x000


/**
 * @macro OSEGW_EPROTOCOL_ERROR
 * @brief
 *    The client got some response data which it did not expect.
 * @long
 *    The extra parameter contains a number that might be helpful in
 *    a protocol debug session.
 */

#define OSEGW_EPROTOCOL_ERROR   0x201


/**
 * @macro OSEGW_EUNKNOWN_ECODE
 * @brief
 *    The gateway server has responded to a request with an unknown
 *    error code.
 * @long
 *    The extra parameter contains the servers error code.
 */

#define OSEGW_EUNKNOWN_ECODE    0x202

/**
 * @macro OSEGW_ECAN_NOT_CONNECT
 * @brief
 *    The client is unable to connect to the given gateway address.
 * @long
 *    The xtra parameter contains the error code from the native
 *    communiction protocol's implementation. (I.e. the errno value).
 */

#define OSEGW_ECAN_NOT_CONNECT  0x203


/**
 * @macro OSEGW_ECONNECTION_LOST
 * @brief
 *    The client can no longer communicate with the gateway.
 * @long
 *    The extra parameter contains the error code from the native
 *    communiction protocol's implementation. (I.e. the errno value).
 */

#define OSEGW_ECONNECTION_LOST  0x204


/**
 * @macro OSEGW_ENO_CLIENT_MEMORY
 * @brief
 *    The client can not allocate memory for internal use.
 * @long
 *    The extra parameter contains the number of bytes needed.
 */

#define OSEGW_ENO_CLIENT_MEMORY 0x205


/**
 * @macro OSEGW_ELOGIN_FAILED
 * @brief
 *    The client was unable to login to the given gateway using the
 *    given user_auth string.
 */

#define OSEGW_ELOGIN_FAILED     0x206


/**
 * @macro OSEGW_EUNSUPPORTED_AUTH
 * @brief
 *    The client and the server are unable to negotiate (and agree)
 *    upon any authentication scheme.
 */

#define OSEGW_EUNSUPPORTED_AUTH 0x207


/**
 * @macro OSEGW_ECONNECTION_TIMEDOUT
 * @brief
 *    The client's communication with the gateway server timed out.
 * @long
 *    The extra parameter contains the time (in milliseconds) that we have
 *    waited for a response so far.
 *    The error handler should return OSEGW_TRUE if we want to continue to wait
 *    for a response. All other return values from the error handler will render
 *    an OSEGW_ECONNECTION_LOST error.
 */

#define OSEGW_ECONNECTION_TIMEDOUT 0x208


/**
 * @macro OSEGW_EBUFFER_TOO_LARGE
 * @brief
 *    Too large signal buffer requested.
 * @long
 *    The extra parameter contains the  size requested.
 */

#define OSEGW_EBUFFER_TOO_LARGE     0x11

/**
 * @macro OSEGW_ENO_USER_SIGSPACE
 * @brief
 *    Out of space when trying to allocate a signal.
 */

#define OSEGW_ENO_USER_SIGSPACE     0x20


/**
 * @macro OSEGW_EUSED_NIL_POINTER
 * @brief
 *    The caller tried to operate on the OSEGW_NIL pointer.
 * @long
 *    The buffer has probably been sent or freed already. The extra
 *    parameter contains the address of the signal pointer that
 *    points to OSEGW_NIL.
 */

#define OSEGW_EUSED_NIL_POINTER     0x31


/**
 * @macro OSEGW_EILLEGAL_PROCESS_ID
 * @brief
 *    An illegal block or process id was presented to the kernel.
 * @long
 *    The extra parameter contains the offending id.
 */

#define OSEGW_EILLEGAL_PROCESS_ID   0x32


/**
 * @macro OSEGW_ENOT_SIG_OWNER
 * @brief
 *    The given OSEGW object is not the owner of the specified signal
 *    buffer.
 * @long
 *    The extra parameter contains the address of the signal buffer.
 */

#define OSEGW_ENOT_SIG_OWNER        0x5F


/**
 * @macro OSEGW_EBAD_PARAMETER
 * @brief
 *    An invalid parameter was used in a system call.
 * @long
 *    The operating system checks many of the system call parameters
 *    for unreasonable values. This error code means that one of the
 *    parameters to the indicated system call contained an illegal
 *    value.
 * @long
 *    The extra parameter contains the value of the offending
 *    parameter.
 */

#define OSEGW_EBAD_PARAMETER        0x71


/**
 * @macro OSEGW_ENO_BUFFER_END_MARK
 * @brief
 *    A valid end mark could not be found in the signal buffer
 *    presented to the kernel.
 * @long
 *    The caller seems to have been writing more data than the size
 *    of the buffer allows.
 * @long
 *    The extra parameter contains the address of the signal buffer.
 */

#define OSEGW_ENO_BUFFER_END_MARK   0xA5


/**
 * @macro OSEGW_ETOO_MANY_ATTACHED
 * @brief
 *    Too many signals were attached.
 * @long
 *    The system tables allows only a certain number of attached
 *    signals. This number was exceeded.
 */

#define OSEGW_ETOO_MANY_ATTACHED    0x24


/**
 * @macro OSEGW_EDETACHED_TWICE
 * @brief
 *    An attempt to detach from an already detached process was made.
 * @long
 *    Only one osegw_detach() call may be issued for each
 *    osegw_attach() call made.
 * @long
 *    This error may also occur if osegw_detach() is called with a
 *    bad parameter. The gateway can not understand the difference
 *    in all cases.
 */

#define OSEGW_EDETACHED_TWICE       0x2d


/**
 * @macro OSEGW_EDETACH_AFTER_RECEIVE
 * @brief
 *    An attempt was made to detach from a process when the attached
 *    signal has already been received.
 */

#define OSEGW_EDETACH_AFTER_RECEIVE 0x2f


/**
 * @macro OSEGW_EATTACHED_TO_CALLER
 * @brief
 *    An attempt was made to issue an osegw_attach() to the the
 *    process ID representing the given OSEGW object. Doing so is
 *    illegal.
 */

#define OSEGW_EATTACHED_TO_CALLER   0x53



/*
 ***********************************************************************
 * Callback functions.
 ***********************************************************************
 */

/**
 * @type OSEGW_FOUND_GW
 *
 * @brief
 *    A function of this type is called for every OSE Gateway found
 *    by the osegw_find_gw call.
 *
 * @long
 *    This callback function must be implemented by the user if the
 *    osegw_find_gw() call is used. The osegw_find_gw() call
 *    broadcasts a message that all OSE Gateways will reply to. Each
 *    OSE Gateway that replay will generate a callback to a function of
 *    this type.
 *
 * @field
 *    usr_hd       This pointer is passed on from the caller of
 *                 segw_find_gw().
 * @field
 *    gw_address   This is the address to connect to as stated by the
 *                 found OSE Gateway.
 * @field
 *    gw_name      This string may contain a name of the found gateway
 *                 (or any extra extra information) that the gateway
 *                 wish to announce.
 * @return
 *    Return a non-zero value to stop the search for more OSE Gateways.
 *
 * @seealso osegw_find_gw
 *
 * @example
 *
 *    #include <sys/socket.h>
 *    #include <stdio.h>
 *    #include <string.h>
 *    #include "ose_gw.h"
 *
 *    #define SOME_TIME 10000
 *
 *    #define MAX_GW_ADDRESS_LEN 64
 *    struct GATEWAY_INFO_OBJ
 *    {
 *       const char *name;
 *       char address[MAX_GW_ADDRESS_LEN];
 *    };
 *
 *    OSEGW_BOOLEAN
 *    osegw_found(void *handle,
 *                const char *gw_address,
 *                const char *gw_name)
 *    {
 *       struct GATEWAY_INFO_OBJ *gw_info = (struct GATEWAY_INFO_OBJ *)handle;
 *
 *       if (strcmp(gw_name, gw_info->name) == 0)
 *       {
 *          strncpy(gw_info->address, gw_address, MAX_GW_ADDRESS_LEN);
 *          return OSEGW_TRUE;
 *       }
 *       return OSEGW_FALSE;
 *    }
 *
 *    struct OSEGW *
 *    establish_connection(struct GATEWAY_INFO_OBJ *gw_info,
 *                         const char *client_name)
 *    {
 *       OSEGW_BOOLEAN rv;
 *       struct OSEGW *gw;
 *
 *       rv = osegw_find_gw(OSEGW_STD_BRC_ADDR,
 *                          SOME_TIME,
 *                          osegw_found,
 *                          gw_info);
 *       if (!rv)
 *          return NULL;
 *       else
 *       {
 *          gw = osegw_create(client_name, 0,
 *                            gw_info->address,
 *                            NULL, NULL, NULL);
 *          if (gw == NULL)
 *          {
 *             printf("Could not connect to OSE Gateway <%s>\n",
 *                    gw_info->address);
 *             return NULL;
 *          }
 *       }
 *       return gw;
 *    }
 *
 *    int
 *    main(int argc, char *argv[])
 *    {
 *       struct GATEWAY_INFO_OBJ gw_info;
 *       struct OSEGW *gw;
 *
 *       // The name of the gateway we wish to establish a connection to.
 *       // This name is specified in the configuration file for the
 *       // Gateway.
 *       gw_info.name = "example_gateway";
 *
 *       gw = establish_connection(&gw_info, "example_client");
 *       if (gw == NULL)
 *       {
 *           printf("OSE GATEWAY <%s> was not found.\n",
 *                  gw_info.name);
 *           exit(1);
 *       }
 *
 *       // Do what the client is supposed to do here
 *
 *       // Destroy the client
 *       osegw_destroy(gw);
 *
 *       return 0;
 *    }
 *
 */

typedef OSEGW_BOOLEAN
OSEGW_FOUND_GW(void       *usr_hd,
               const char *gw_address,
               const char *gw_name);


/**
 * @type OSEGW_ERRORHANDLER
 *
 * @brief
 *    Error handlers should be functions of this type.
 *
 * @long
 *    This function is called if a fault is caught by the gateway's
 *    client library functions. The implementation of this function
 *    can separate errors that causes the function to exit and errors
 *    that can be ignored.
 * @long
 *    This library also contains a default error handler that can be
 *    used with or without a custom error handler.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    usr_hd   This pointer is passed on from the caller of osegw_create().
 * @field
 *    ecode    This number describes the error, the error codes all have
 *             the form OSEGW_Exxx, where xxx tells the error cause.
 * @field
 *    extra    This parameter may contain extra error information.
 *
 * @return
 *    Return a OSEGW_TRUE value to ignore the error.
 *    Return a OSEGW_FALSE value to exit prematurely.
 *
 * @seealso osegw_create
 * @seealso osegw_get_error
 * @seealso osegw_reset_error
 *
 * @example
 *
 *     #include <stdio.h>
 *     #include "ose_gw.h"
 *
 *     OSEGW_BOOLEAN error_handler(void           *usr_hd,
 *                                 struct OSEGW   *ose_gw,
 *                                 OSEGW_OSERRCODE ecode,
 *                                 OSEGW_OSERRCODE extra)
 *     {
 *         OSEGW_BOOLEAN fatal = OSEGW_FALSE;
 *
 *         // Check if the error is fatal.
 *         switch (ecode)
 *         {
 *            case OSEGW_ECAN_NOT_CONNECT:
 *               fatal = OSWGW_TRUE;
 *               break;
 *            default:
 *               break;
 *         }
 *
 *         // Handle a fatal error.
 *         if (fatal)
 *         {
 *             fprintf(stderr,
 *                     "OSE Gateway Fatal Error:%x, extra:%x\n",
 *                     ecode,
 *                     extra);
 *             return OSEGW_FALSE;
 *         }
 *
 *         // The error is not fatal
 *         return OSEGW_TRUE;
 *     }
 */

typedef OSEGW_BOOLEAN
OSEGW_ERRORHANDLER(void            *usr_hd,
                   struct OSEGW    *ose_gw,
                   OSEGW_OSERRCODE  ecode,
                   OSEGW_OSERRCODE  extra);

/*
 ***********************************************************************
 * System calls.
 ***********************************************************************
 */

/**
 * @function osegw_find_gw
 *
 * @brief
 *    Find all OSE Gateways on a local network.
 * @long
 *    This call broadcasts an OSE Gateway signature over a local network.
 *    Available Gateways reply to this signature and for each reply
 *    the OSEGW_FOUND_GW function is called.
 *
 * @field
 *    broadcast_address   Broadcast on this address to find OSE Gateways.
 *                        For UDP/IP use "udp://\052:<port>" as address,
 *                        or use the macro OSEGW_STD_BRC_ADDR.
 * @field
 *    timeout             The number of milliseconds to wait.
 * @field
 *    gw_found            A pointer to a function which will be called
 *                        one time for each OSE Gateway found.
 * @field
 *    usr_hd              This pointer will be passed on when the
 *                        gw_found function is called.
 * @return
 *    A non-zero value if the gateway iteration was stopped by the
 *    gw_found function, otherwise it returns zero.
 *
 * @error OSEGW_EBAD_PARAMETER
 *
 * @seealso OSEGW_FOUND_GW
 *
 * @example
 *    See OSEGW_FOUND_GW
 *
 */

OSEGW_BOOLEAN
osegw_find_gw(const char     *broadcast_address,
              OSEGW_OSTIME    timeout,
              OSEGW_FOUND_GW *gw_found,
              void           *usr_hd);

/**
 * @function osegw_create
 *
 * @brief
 *    Create an OSE Gateway connection.
 * @long
 *    This call creates an OSEGW object and establishes a connection
 *    with the OSE Gateway on a given address.
 *
 * @field
 *    my_name      Create a representation of me in the OSE world with
 *                 this name ...
 * @field
 *    user         ... and this user number.
 * @field
 *    gw_address   Connect to the OSE Gateway at this address.
 *                 For TCP/IP use "tcp://<host>:<port>" as address.
 * @field
 *    user_auth    User authentication string. Normally in the
 *                 "username:password" form. Set this parameter to NULL
 *                 if no authentication is used.
 * @field
 *    err_hnd      A pointer to an error handler for this connection.
 * @field
 *    usr_hd       This pointer will be passed on when the error handler
 *                 is called.
 * @return
 *    A handle that is to be used for this connection, or NULL if a
 *    connection could not be established.
 *
 * @restriction
 *    A user error handler must be provided to gain knowledge about
 *    failiures during the creation phase. The OSEGW object given
 *    to the error handler may be NULL.
 *
 * @error OSEGW_ECAN_NOT_CONNECT
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_EUNSUPPORTED_AUTH
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 * @error OSEGW_ELOGIN_FAILED
 * @error OSEGW_ENO_CLIENT_MEMORY
 *
 * @seealso osegw_detroy
 *
 * @example
 *
 *    #include <sys/socket.h>
 *    #include <stdio.h>
 *    #include "ose_gw.h"
 *
 *    #define OSEGW_DAEMON_ADDRESS "tcp://localhost:12357"
 *    #define LONG_TIME 1000000
 *    #define HUNT_SIGNO 0xAA
 *    #define SIGNO 0xBB
 *    #define NR_SIGNALS 100
 *    static const OSEGW_SIGSELECT any_sig[] = { 0 };
 *    static const OSEGW_SIGSELECT hunt_sig[] = {1, HUNT_SIGNO};
 *
 *    int
 *    main(int argc, char *argv[])
 *    {
 *       struct OSEGW *gw;
 *       union OSEGW_SIGNAL *signal;
 *       OSEGW_PROCESS echo_pid;
 *       int i;
 *
 *       // Create the Client
 *       gw = osegw_create("client1", 0,
 *                         OSEGW_DAEMON_ADDRESS,
 *                         NULL, NULL, NULL);
 *       if (gw == NULL)
 *       {
 *          printf("*** ERROR *** Could not connect to OSE Gateway\n");
 *          exit(1);
 *       }
 *
 *       // Hunt for the other client
 *       signal = osegw_alloc(gw, sizeof(OSEGW_SIGSELECT), HUNT_SIGNO);
 *       (void)osegw_hunt(gw, "client2", 0, NULL, &signal);
 *
 *       // Receive the hunt signal
 *       signal = osegw_receive_w_tmo(gw, LONG_TIME, hunt_sig);
 *       if (signal == NULL)
 *       {
 *          printf("*** ERROR *** Could not find the other client\n");
 *          osegw_destroy(gw);
 *          exit(1);
 *       }
 *
 *       // Get the pid of the echo process from the returned hunt signal
 *       echo_pid = osegw_sender(gw, &signal);
 *       osegw_free_buf(gw, &signal);
 *
 *       // Send signals to the other client and receive signals from it
 *       for (i = 0; i < NR_SIGNALS; i++)
 *       {
 *          signal = osegw_alloc(gw, sizeof(OSEGW_SIGSELECT), SIGNO);
 *          osegw_send(gw, &signal, echo_pid);
 *
 *          signal = osegw_receive_w_tmo(gw, LONG_TIME, any_sig);
 *          if (signal == NULL)
 *          {
 *             printf("*** ERROR *** No signal received from the other client\n");
 *             osegw_destroy(gw);
 *             exit(1);
 *          }
 *          osegw_free_buf(gw, &signal);
 *       }
 *
 *       // Destroy the client
 *       osegw_destroy(gw);
 *
 *       return 0;
 *    }
 *
 */

struct OSEGW *
osegw_create(const char         *my_name,
             OSEGW_OSUSER        user,
             const char         *gw_address,
             const char         *user_auth,
             OSEGW_ERRORHANDLER *err_hnd,
             void               *usr_hd);

/**
 * @function osegw_destroy
 *
 *
 * @brief
 *    Close an OSE Gateway connection and release the OSEGW object.
 * @long
 *    This function also returns all signal buffers owned by this
 *    OSEGW object.
 *
 * @field
 *    ose_gw   The connection handle.
 *
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_create
 *
 * @example
 *    See osegw_create()
 */

void
osegw_destroy(struct OSEGW *ose_gw);

/**
 * @function osegw_get_pid
 *
 * @brief
 *    Return the ID of the OSE process representing the given OSE Gateway
 *    object.
 *
 * @field
 *    ose_gw  The connection handle.
 *
 * @return
 *    The ID of the OSE process representing the given OSE Gateway object.
 */

OSEGW_PROCESS
osegw_get_pid(struct OSEGW *ose_gw);

/**
 * @function osegw_alloc
 *
 * @brief
 *    Allocates an OSE type signal buffer of the specified size.
 * @long
 *    The specified sig_no (signal number) is entered in the first
 *    location in the new buffer.
 * @long
 *    The given OSEGW object will become the owner of the signal.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    size     The requested size of the buffer.
 * @field
 *    sig_no   The signal number, which will be placed first in the
 *             allocated buffer.
 *
 * @return
 *    A pointer to a union OSEGW_SIGNAL buffer.
 *
 * @restriction
 *    The minimum size that can be allocated is sizeof(OSEGW_SIGSELECT).
 *
 * @error
 *    OSEGW_ENO_USER_SIGSPACE
 *
 * @seealso osegw_free_buf
 *
 * @example osegw_create()
 *
 */

union OSEGW_SIGNAL *
osegw_alloc(struct OSEGW    *ose_gw,
            OSEGW_OSBUFSIZE  size,
            OSEGW_SIGSELECT  sig_no);

/**
 * @function osegw_free_buf
 *
 * @brief
 *    Free an OSE type signal.
 * @long
 *    This system call will enter OSWGW_NIL into the caller's signal
 *    pointer to avoid accidental reuse of the buffer. The given OSEGW
 *    object is no longer the owner of the signal.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    sig      A pointer to a pointer to a signal buffer.
 *
 * @restriction
 *    It is an error to free a buffer owned by another OSEGW object.
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 *
 * @seealso osegw_alloc
 *
 * @example osegw_create()
 */

void
osegw_free_buf(struct OSEGW        *ose_gw,
               union OSEGW_SIGNAL **sig);

/**
 * @function osegw_send
 *
 * @brief
 *    Sends an OSE type signal buffer to a specified addressee
 *    process.
 * @long
 *    This system call will enter OSWGW_NIL into the caller's signal
 *    pointer to avoid accidental reuse of the buffer. The given OSEGW
 *    object is no longer the owner of the signal.
 * @long
 *    If the addressee process has terminated, the signal is quietly
 *    killed.  The caller will never know. Use the osegw_attach()
 *    mechanism to handle this if necessary.
 *
 * @field
 *    ose_gw  The connection handle.
 * @field
 *    sig     A pointer to a pointer to a signal buffer.
 * @field
 *    pid     The ID of the process the signal will be sent to.
 *
 * @restriction
 *    Only signals owned by the connection object can be sent.
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_receive
 * @seealso osegw_receive_w_tmo
 * @seealso osegw_init_async_receive
 * @seealso osegw_alloc
 *
 * @example osegw_create()
 *
 */

void
osegw_send(struct OSEGW        *ose_gw,
           union OSEGW_SIGNAL **sig,
           OSEGW_PROCESS        pid);

/**
 * @function osegw_send_w_s
 *
 * @brief
 *    Short for send with sender. Works like osegw_send(), except that the
 *    signal buffer is tagged with the specified process ID in place of the
 *    caller's.
 * @long
 *    This system call will enter OSWGW_NIL into the caller's signal
 *    pointer to avoid accidental reuse of the buffer. The given OSEGW
 *    object is no longer the owner of the signal.
 * @long
 *    If the addressee process or the specified sender process has terminated,
 *    the signal is quietly killed. The caller will never know. Use the
 *    osegw_attach() mechanism to handle this if necessary.
 *
 * @field
 *    ose_gw  The connection handle.
 * @field
 *    sig     A pointer to a pointer to a signal buffer.
 * @field
 *    from    The ID of the process specified as sender.
 * @field
 *    to      The ID of the process the signal will be sent to.
 *
 * @restriction
 *    Only signals owned by the connection object can be sent.
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_send
 * @seealso osegw_receive
 * @seealso osegw_receive_w_tmo
 * @seealso osegw_init_async_receive
 * @seealso osegw_alloc
 */

void
osegw_send_w_s(struct OSEGW        *ose_gw,
               union OSEGW_SIGNAL **sig,
               OSEGW_PROCESS        from,
               OSEGW_PROCESS        to);

/**
 * @function osegw_receive
 *
 * @brief
 *    Receives OSE type signal from the signal queue of the given
 *    OSEGW object.
 * @long
 *    If an appropriate signal is not immediately available, the
 *    caller pends until an appropriate signal is sent to the caller
 *    by some one.
 * @long
 *    The given OSEGW object will become the owner of the received
 *    signal.
 * @long
 *    Sig_sel points to an array containing a list of signal numbers
 *    to be received. Receive returns to the caller when a signal
 *    matching any of the specified signal numbers is found.
 * @long
 *    The first position in sig_sel contains the number of entries in
 *    the list that follows.
 * @long
 *    If the number of entries is zero, any signal number is
 *    accepted.
 * @long
 *    A "negative receive specification" feature is supported. This
 *    means that if the first location of the sigsel array contains a
 *    negative count, then any signal except those that match the
 *    sigsel array is received. This feature effectively inverts the
 *    semantics of the osegw_receive(), osegw_receive_w_tmo() and
 *    osegw_init_async_receive() calls, providing a means of holding
 *    back certain signals.
 * @long
 *    The SIGSELECT type is an unsigned type, so using a negative
 *    receive specification requires the count in the sigsel array to
 *    be initialized with a proper cast expression.
 *
 * @field
 *    ose_gw    The connection handle.
 * @field
 *    sig_sel   A pointer of an array of the signal numbers to receive.
 *
 * @return
 *    Returns a pointer to the received signal buffer. This buffer is
 *    owned by the given OSEGW object from that moment.
 *
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_NO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_send
 * @seealso osegw_receive_w_tmo
 * @seealso osegw_init_async_receive
 * @seealso osegw_alloc
 */

union OSEGW_SIGNAL *
osegw_receive(struct OSEGW          *ose_gw,
              const OSEGW_SIGSELECT *sig_sel);

/**
 * @function osegw_receive_w_tmo
 *
 * @brief
 *    Short for receive with timeout.
 * @long
 *    Works like osegw_receive(), except that the caller is suspended
 *    no longer than the number of milliseconds specified in the
 *    timeout parameter.
 * @long
 *    If the requested signal has not arrived by then, the OSEGW_NIL
 *    pointer is returned.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    tmo      The number of milliseconds to wait. If 0, the signal queue
 *             is checked and the call returns without delay except for
 *             communication delays. The unit is milli seconds (ms).
 * @field
 *    sig_sel  A pointer of an array of the signal numbers to receive.
 *
 * @return
 *    A pointer to the received signal buffer or the OSEGW_NIL
 *    pointer if no signal arrived within the specified
 *    timeout.
 *
 * @restriction
 *    The true timeout time is the given tmo plus time for
 *    communication. The time for communication varies bewteen
 *    different systems.
 *
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_NO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_send
 * @seealso osegw_receive
 * @seealso osegw_init_async_receive
 * @seealso osegw_alloc
 *
 * @example osegw_create()
 */

union OSEGW_SIGNAL *
osegw_receive_w_tmo(struct OSEGW          *ose_gw,
                    OSEGW_OSTIME           tmo,
                    const OSEGW_SIGSELECT *sig_sel);

/**
 * @function osegw_sender
 *
 * @brief
 *    Finds out who last sent a specified signal buffer.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    sig      A pointer to a pointer to a signal buffer.
 *
 * @return
 *    The process ID of the sender or the owner's ID if the signal was
 *    never sent.
 *
 * @restriction
 *    Only signal buffer owned by the connection object can be
 *    examined.
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 *
 * @seealso osegw_receive
 *
 * @example None
 *
 */

OSEGW_PROCESS
osegw_sender(struct OSEGW        *ose_gw,
             union OSEGW_SIGNAL **sig);

/**
 * @function osegw_sigsize
 *
 * @brief
 *    Examines an OSE type signal buffer and reports the size that
 *    was requested when the buffer was allocated.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    sig      A pointer to a pointer to a signal buffer.
 *
 * @return
 *    The numer of bytes requested when the signal buffer was
 *    allocated.
 *
 * @restriction
 *    Only signal buffer owned by the connection object can be
 *    examined.
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 *
 * @seealso osegw_alloc
 */

OSEGW_OSBUFSIZE
osegw_sigsize(struct OSEGW        *ose_gw,
              union OSEGW_SIGNAL **sig);

/**
 * @function osegw_get_blocking_object
 *
 * @brief
 *    Returns a pointer to the native object used for Gateway
 *    client to server communication.
 *
 *    This object can be used by the application in a host native
 *    wait type of expression. If the blocking object is a socket,
 *    the application can get hold of the socket by using this
 *    function and use in in a native select() or poll() expression.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    type     A pointer to a pointer to a variable in which the
 *              type of the blocking object will be placed.
 *
 * @return
 *    A pointer to the native communication object.
 *
 * @seealso osegw_init_async_receive
 * @seealso osegw_async_receive
 * @seealso osegw_cancel_async_receive
 *
 * @example osegw_async_receive()
 */

void *
osegw_get_blocking_object(struct OSEGW    *ose_gw,
                          OSEGW_OSADDRESS *type);

/**
 * @function osegw_init_async_receive
 *
 * @brief
 *    Register a sigselect mask for an async type of receive.
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    sig_sel  A pointer of an array of the signal numbers to receive.
 *
 * @restriction
 *    The OSEGW connection can not be used until a signal has been received,
 *    with osegw_init_async_receive or the receive has be canceled with
 *    osegw_cancel_async_receive.
 *
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 *
 * @seealso osegw_get_blocking_object
 * @seealso osegw_async_receive
 * @seealso osegw_cancel_async_receive
 *
 * @example osegw_async_receive()
 */

void
osegw_init_async_receive(struct OSEGW          *ose_gw,
                         const OSEGW_SIGSELECT *sig_sel);

/**
 * @function osegw_async_receive
 *
 * @brief
 *    Receive an OSE type signal.
 * @long
 *    The caller is suspended until a signal that matches the sigselect
 *    mask given in a previous call to osegw_init_async_receive() is
 *    received.
 *
 * @field
 *    ose_gw   The connection handle.
 *
 * @return
 *    A pointer to a received signal buffer.
 *
 * @restriction
 *    The connection handle must be initialized with a call to
 *    osegw_init_async_receive() before this function is called.
 *
 * @error OSEGW_NO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_get_blocking_object
 * @seealso osegw_init_async_receive
 * @seealso osegw_cancel_async_receive
 * @seealso osegw_receive
 * @seealso osegw_receive_w_tmo
 *
 * @example
 *
 *    #include <sys/socket.h>
 *    #include <stdio.h>
 *    #include "ose_gw.h"
 *
 *    #define OSEGW_DAEMON_ADDRESS "tcp://localhost:12357/"
 *    #define LONG_TIME 1000000
 *    static const OSEGW_SIGSELECT any_sig[] = { 0 };
 *
 *    static void
 *    handle_error(void)
 *    {
 *        exit(1);
 *    }
 *
 *    static int
 *    get_max_value(int v1, int v2)
 *    {
 *       if (v1 > v2)
 *          return v1;
 *       else
 *          return v2;
 *    }
 *
 *    int
 *    main(int argc, char *argv[])
 *    {
 *       struct OSEGW *gw_client1;
 *       struct OSEGW *gw_client2;
 *       union OSEGW_SIGNAL *signal;
 *       OSEGW_PROCESS pid_client1;
 *       OSEGW_PROCESS pid_client2;
 *       int sock_client1;
 *       int sock_client2;
 *       int max_val;
 *       int nr_signals_left;
 *       int rv;
 *       fd_set rfds;
 *
 *       // Create the Clients
 *       gw_client1 = osegw_create("client1", 0,
 *                                 OSEGW_DAEMON_ADDRESS,
 *                                 NULL, NULL, NULL);
 *       if (gw_client1 == NULL)
 *       {
 *          printf("*** ERROR *** Could not connect to OSE Gateway\n");
 *          exit(1);
 *       }
 *       gw_client2 = osegw_create("client2", 0,
 *                                 OSEGW_DAEMON_ADDRESS,
 *                                 NULL, NULL, NULL);
 *       if (gw_client2 == NULL)
 *       {
 *          printf("*** ERROR *** Could not connect to OSE Gateway\n");
 *          exit(1);
 *       }
 *
 *       pid_client1 = osegw_get_pid(gw_client1);
 *       pid_client2 = osegw_get_pid(gw_client2);
 *
 *       sock_client1 = *(int *)osegw_get_blocking_object(gw_client1, NULL);
 *       sock_client2 = *(int *)osegw_get_blocking_object(gw_client2, NULL);
 *
 *       // Client1 sends signals to client 2
 *       signal = osegw_alloc(gw_client1, 10, 0x01);
 *       osegw_send(gw_client1, &signal, pid_client2);
 *       signal = osegw_alloc(gw_client1, 10, 0x01);
 *       osegw_send(gw_client1, &signal, pid_client2);
 *
 *       // Client2 sends signals to client 1
 *       signal = osegw_alloc(gw_client2, 10, 0x01);
 *       osegw_send(gw_client2, &signal, pid_client1);
 *       signal = osegw_alloc(gw_client2, 10, 0x01);
 *       osegw_send(gw_client2, &signal, pid_client1);
 *
 *       // Start the asyncronous receive mode for both clients
 *       osegw_init_async_receive(gw_client1, any_sig);
 *       osegw_init_async_receive(gw_client2, any_sig);
 *
 *       // Receive all four signals
 *       nr_signals_left = 4;
 *       while (nr_signals_left > 0)
 *       {
 *          FD_ZERO(&rfds);
 *          FD_SET(sock_client1, &rfds);
 *          FD_SET(sock_client2, &rfds);
 *          max_val = get_max_value(sock_client1, sock_client2);
 *
 *          rv = select(max_val + 1, &rfds, NULL, NULL, NULL);
 *          if (rv <= 0)
 *             handle_error();
 *          else
 *          {
 *             if (FD_ISSET(sock_client1, &rfds))
 *             {
 *                signal = osegw_async_receive(gw_client1);
 *                osegw_free_buf(gw_client1, &signal);
 *                nr_signals_left--;
 *                osegw_init_async_receive(gw_client1, any_sig);
 *             }
 *             if (FD_ISSET(sock_client2, &rfds))
 *             {
 *                signal = osegw_async_receive(gw_client2);
 *                osegw_free_buf(gw_client2, &signal);
 *                nr_signals_left--;
 *                osegw_init_async_receive(gw_client2, any_sig);
 *             }
 *          }
 *       }
 *
 *       // Cancel async receive for both clients
 *       osegw_cancel_async_receive(gw_client1);
 *       osegw_cancel_async_receive(gw_client2);
 *
 *       // Destroy both clients
 *       osegw_destroy(gw_client1);
 *       osegw_destroy(gw_client2);
 *
 *       return 0;
 *    }
 *
 */

union OSEGW_SIGNAL *
osegw_async_receive(struct OSEGW *ose_gw);

/**
 * @function osegw_cancel_async_receive
 *
 * @brief
 *    Cancel any started async receive requests.
 *
 * @field
 *    ose_gw   The connection handle.
 *
 * @return
 *    A pointer to a "too late to cancel" received signal buffer or
 *    the OSEGW_NIL pointer if the cancel operation was "truly
 *    successful".
 *
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_get_blocking_object
 * @seealso osegw_init_async_receive
 * @seealso osegw_async_receive
 *
 * @example osegw_async_receive
 */

union OSEGW_SIGNAL *
osegw_cancel_async_receive(struct OSEGW *ose_gw);

/**
 * @function osegw_hunt
 *
 * @brief
 *    Searches for a process by name and updates the pid_ parameter
 *    with the process ID of the named process.
 * @long
 *    The pid_ parameter may be set to NULL if no return value
 *    variable is provided. This may be convenient when a hunt_sig is
 *    present.
 * @long
 *    Only processes with the specified user number are searched
 *    for. A user parameter set to zero specifies the caller's user
 *    number.
 * @long
 *    If the process is found immediately, the ID of the found
 *    process is returned in the pid_ variable.
 * @long
 *    An optional hunt signal may be specified. This signal is stored
 *    in the OSE Gateway until the process appears on the network or
 *    the caller terminates. Hunt_sig may be set to NULL to indicate
 *    that no hunt signal is provided.
 * @long
 *    When the process is found or created, the hunt signal is
 *    returned to the caller, and the process ID of the found process
 *    can be extracted with the osegw_sender() call.
 * @long
 *    The hunt signal is immediately returned if the process was
 *    immediately found, i.e if a hunt signal is specified, it should
 *    always be received, either immediately or later on.
 *
 * @field
 *    ose_gw     The connection handle.
 * @field
 *    name       A pointer to the specified process name.
 * @field
 *    user       The user number.
 * @field
 *    pid_       A pointer to an variable of type OSEGW_PROCESS in which
 *                the ID of an immediately found process will be stored.
 * @field
 *    hunt_sig   A pointer to a pointer to the hunt signal, if specified.
 *
 * @return
 *    The pid_ parameter, if present, is updated with the found
 *    process ID. The ID is guaranteed to be invalid if the process
 *    was not immediately found.
 *
 *    The call returns zero if the process could not be found
 *    immediately. If a hunt signal was given by the caller, it is
 *    stored in the OSE Gateway until a matching process appears at a
 *    later time.
 *
 *    Returns a non-zero value if the process was found
 *    immediately. Any hunt signal provided is returned to the
 *    caller.
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_attach
 *
 * @example
 *    #include "ose_gw.h"
 *
 *    #define HUNT_SIG_NO 42
 *    struct HUNT_SIGNAL
 *    {
 *        OSEGW_SIGSELECT sig_no;
 *    };
 *
 *    union OSEGW_SIGNAL
 *    {
 *        OSEGW_SIGSELECT sig_no;
 *        struct HUNT_SIGNAL hunt_signal;
 *    };
 *
 *    // This funtion hunts a process specified by the parameter name and
 *    // then blocks until the process is terminated.
 *    void supervise_proc(struct OSEGW *ose_gw, const char *name)
 *    {
 *        static const OSEGW_SIGSELECT select_hunt_sig[] = {1, HUNT_SIGN_O};
 *        static const OSEGW_SIGSELECT select_attach_sig[] =
 *            {1, OSEGW_ATTACH_SIG};
 *        union OSEGW_SIGNAL *sig;
 *        OSEGW_PROCESS hunted_proc;
 *        OSEGW_OSATTREF attref;
 *
 *        // Hunt for the process with hunt signal
 *        sig = osegw_alloc(sizeof(struct HUNT_SIGNAL), HUNT_SIG_NO);
 *        (void)osegw_hunt(ose_gw, name, 0, NULL, &sig);
 *
 *        // Wait for the hunt signal
 *        sig = osegw_receive(ose_gw, select_hunt_sig);
 *
 *        // Save the hunted process' pricess id.
 *        hunted_proc = osegw_sender(ose_gw, &sig);
 *
 *        osegw_free_buf(ose_gw, &sig);
 *
 *        // Supervise the excistense of the found process, use the
 *        // default return signal from the kernel.
 *        attref = osegw_attach(NULL, hunted_proc);
 *
 *        // Wait for the hunted process to be terminated
 *        sig = osegw_receive(ose_gw, select_attach_sig);
 *        osegw_free_buf(ose_gw, &sig);
 *    }
 */

OSEGW_OSBOOLEAN
osegw_hunt(struct OSEGW        *ose_gw,
           const char          *name,
           OSEGW_OSUSER         user,
           OSEGW_PROCESS       *pid_,
           union OSEGW_SIGNAL **hunt_sig);

/**
 * @function osegw_attach
 *
 * @brief
 *    Attach to a remote process.
 * @long
 *    This call is used to detect if a process is terminated. The specified
 *    signal is stored within OSE Gateway until the process is killed and
 *    then sent back to the caller.
 * @long
 *    If no signal is specified, (i.e. the sig parameter is set to
 *    NULL), the OSE Gateway automatically allocated a default attach
 *    signal with signal number OSEGW_OS_ATTACH_SIG.
 * @long
 *    If the attached process or block is killed, this buffer is sent
 *    back to the caller by the kernel. The buffer will be sent back
 *    immediately to the caller if the process or block is already
 *    dead when issuing the attach.
 * @long
 *    Normal buffer examination calls, like osegw_sender() and
 *    osegw_sigsize(), work on the returned buffer. Sender is set to
 *    the process ID of the killed process.
 *
 * @field
 *    ose_gw       The connection handle.
 * @field
 *    sig          A pointer to a pointer to a signal buffer.
 * @field
 *    pid          The ID of the block, process or segment to attach to.
 *
 * @return
 *    A reference ID that may be used in a subsequent call to
 *    osegw_detach().
 *
 * @seealso osegw_detach
 *
 * @error OSEGW_EBAD_PARAMETER
 * @error OSEGW_EUSED_NIL_POINTER
 * @error OSEGW_ENO_BUFFER_END_MARK
 * @error OSEGW_ENOT_SIG_OWNER
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 *
 * @example
 *    See osegw_hunt() and osegw_detach().
 */

OSEGW_OSATTREF
osegw_attach(struct OSEGW        *ose_gw,
             union OSEGW_SIGNAL **sig,
             OSEGW_PROCESS        pid);

/**
 * @function osegw_detach
 *
 * @brief
 *    Removes an OSE type signal previously attached by the caller.
 * @long
 *    The attref parameter contains a pointer to the reference ID
 *    which was returned by the previous call to osegw_attach().
 *
 * @field
 *    ose_gw   The connection handle.
 * @field
 *    attref   A pointer to the reference ID returned by a previous
 *             call to osegw_attach().
 *
 * @restriction
 *    It is illegal to detach a signal already received and freed by
 *    the caller.
 *
 * @error OSEGW_EBUFFER_TOO_LARGE
 * @error OSEGW_ENO_CLIENT_MEMORY
 * @error OSEGW_ECONNECTION_TIMEDOUT
 * @error OSEGW_ECONNECTION_LOST
 *
 * @seealso osegw_attach
 *
 * @example
 *    #include "ose_gw.h"
 *
 *    #define HUNT_SIG_NO 42
 *    struct HUNT_SIGNAL
 *    {
 *        OSEGW_SIGSELECT sig_no;
 *    };
 *
 *    union OSEGW_SIGNAL
 *    {
 *        OSEGW_SIGSELECT sig_no;
 *        struct HUNT_SIGNAL hunt_signal;
 *    };
 *
 *    // This funtion hunts a process specified by the parameter name and
 *    // does some communication. Afterwards it checks if the hunted
 *    // process is still alive to make sure that the communication
 *    // succeeded.
 *    void controlled_comm(struct OSEGW *ose_gw, const char *name)
 *    {
 *        static const OSEGW_SIGSELECT select_hunt_sig[] = {1, HUNT_SIGN_O};
 *        static const OSEGW_SIGSELECT select_attach_sig[] =
 *            {1, OSEGW_ATTACH_SIG};
 *        union OSEGW_SIGNAL *sig;
 *        OSEGW_PROCESS hunted_proc;
 *        OSEGW_OSATTREF attref;
 *
 *        // Hunt for the process with hunt signal
 *        sig = osegw_alloc(sizeof(struct HUNT_SIGNAL), HUNT_SIG_NO);
 *        (void) osegw_hunt(ose_gw, name, 0, NULL, &sig);
 *
 *        // Wait for the hunt signal
 *        sig = osegw_receive(ose_gw, select_hunt_sig);
 *
 *        // Save the hunted process' process id.
 *        hunted_proc = osegw_sender(ose_gw, &sig);
 *
 *        osegw_free_buf(ose_gw, &sig);
 *
 *        // Supervise the excistense of the found process, use the
 *        // default return signal from the kernel.
 *        attref = osegw_attach(NULL, hunted_proc);
 *
 *        // Do communication with the hunted process here.
 *
 *        // Check if the hunted process is still alive, because then
 *        // it can be assumed that the communication succeeded.
 *        sig = osegw_receive_w_tmo(ose_gw, 0, select_attach_sig);
 *        if (if sig != OSEGW_NIL)
 *        {
 *            if (osegw_sender(ose_gw, &sig) != hunted_proc)
 *            {
 *               // The process is still alive and we don't need to
 *               // supervise it anymore, detach the signal.
 *               osegw_detach(ose_gw, &hunted_proc);
 *            }
 *            osegw_free_buf(ose_gw, &sig);
 *        }
 *    }
 */

void
osegw_detach(struct OSEGW   *ose_gw,
             OSEGW_OSATTREF *attref);

/**
 * @function osegw_get_error
 *
 * @brief
 *    Return error code from OSE Gateway object.
 * @long
 *    If an error is detected by a function this error code is
 *    updated with an error code before an optional user error
 *    handler is called.
 *
 * @field
 *     ose_gw   The connection handle.
 *
 * @return
 *     The error code.
 *
 * @seealso osegw_reset_error
 *
 * @example
 *
 *    #include <stdio.h>
 *    #include "ose_gw.h"
 *
 *    #define SIG_NO 42
 *
 *    void host_process(const char *dest_proc_name)
 *    {
 *        struct OSEGW *gw_obj;
 *        union OSEGW_SIGNAL *sig;
 *        OSEGW_OSERRCODE ecode;
 *
 *        // Create a client with the default error handler only.
 *        // The client connects to an OSE Gateway located on the
 *        // localhost with TCP port number TCP_PORT.
 *        //
 *        gw_obj = osegw_create("sig_sender", 0,
 *                              "tcp://localhost:4001",
 *                              NULL, NULL, NULL);
 *
 *        // If the creation of the OSEGW object failed, the default
 *        // error handler can not be used because there is no object
 *        // to refer to. If an error code is important during creation
 *        // an user error handler must be specified.
 *        if (gw_obj == NULL)
 *        {
 *            fprintf(stderr, "*** ERROR *** Creation failed\n");
 *            return;
 *        }
 *
 *        // Allocate an OSEGW_SIGNAL that only contains the
 *        // signal number.
 *        sig = osegw_alloc(gw_obj, sizeof(OSEGW_SIGSELECT), SIGNO);
 *        if (osegw_get_error(gw_obj) != OSEGW_OK)
 *        {
 *           fprintf(stderr, "*** ERROR *** Signal Allocation Failed\n");
 *           osegw_destroy(gw_obj);
 *           return;
 *        }
 *
 *        // Hunt for the destination process
 *        (void) = osegw_hunt(gw_obj, dest_proc_name, 0, NULL, &sig);
 *        ecode = osegw_get_error(gw_obj);
 *        switch (ecode)
 *        {
 *        case OSEGW_OK:
 *           break;
 *        case OSEGW_EBAD_PARAMETER:
 *           fprintf(stderr, "*** ERROR *** OSEGW_EBAD_PARAMETER\n");
 *           break;
 *        case OSEGW_EUSED_NIL_POINTER:
 *           fprintf(stderr, "*** ERROR *** OSEGW_EUSED_NIL_POINTER\n");
 *           break;
 *        case OSEGW_ENO_BUFFER_END_MARK:
 *           fprintf(stderr, "*** ERROR *** OSEGW_ENO_BUFFER_END_MARK\n");
 *           break;
 *        case OSEGW_ENOT_SIG_OWNER:
 *           fprintf(stderr, "*** ERROR *** OSEGW_ENOT_SIG_OWNER\n");
 *           break;
 *        case OSEGW_EBUFFER_TOO_LARGE:
 *           fprintf(stderr, "*** ERROR *** OSEGW_EBUFFER_TOO_LARGE\n");
 *           break;
 *        case OSEGW_ENO_CLIENT_MEMORY:
 *           fprintf(stderr, "*** ERROR *** OSEGW_ENO_CLIENT_MEMORY\n");
 *           break;
 *        case OSEGW_ECONNECTION_LOST:
 *           fprintf(stderr, "*** ERROR *** OSEGW_ECONNECTION_LOST\n");
 *           break;
 *        default:
 *           fprintf(stderr, "*** ERROR *** UNKNOWN ERROR\n");
 *           break;
 *        }
 *
 *        // receive hunt signal and communicate here
 *
 *        // Close the connection and release the OSEGW object.
 *        osegw_destroy(gw_obj);
 *    }
 *
 */

OSEGW_OSERRCODE
osegw_get_error(struct OSEGW *ose_gw);

/**
 * @function osegw_reset_error
 *
 * @brief
 *    Reset error in the OSE Gateway object.
 * @long
 *    Since the error code in the OSE Gateway object is only updated
 *    in case of error it has to be resetted to be useful for further
 *    checks.
 *
 * @field
 *    ose_gw   The connection handle.
 *
 * @seealso osegw_get_error
 */

void
osegw_reset_error(struct OSEGW *ose_gw);

#endif
