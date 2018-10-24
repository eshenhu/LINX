/* COPYRIGHT-ENEA-SRC-R2 *
 **************************************************************************
 * Copyright (C) 2004-2006 by Enea Software AB.
 * All rights reserved.
 *
 * This Software is furnished under a software license agreement and
 * may be used only in accordance with the terms of such agreement.
 * Any other use or reproduction is prohibited. No title to and
 * ownership of the Software is hereby transferred.
 *
 * PROPRIETARY NOTICE
 * This Software consists of confidential information.
 * Trade secret law and copyright law protect this Software.
 * The above notice of copyright on this Software does not indicate
 * any actual or intended publication of such Software.
 **************************************************************************
 * COPYRIGHT-END */

#ifndef _OSE_GWP_H
#define _OSE_GWP_H

#ifndef _OseGW_UL_T
#define _OseGW_UL_T
typedef uint32_t OseGW_UL;
#endif

#define OseGW_ProtocolVersion        100

#define OseGW_StatusOk               ( (OseGW_UL)0)
#define OseGW_StatusErr              (~(OseGW_UL)0)
#define OseGW_StatusAuthentErr      ((~(OseGW_UL)0) - 1UL)

/* Payload types. */
#define OseGW_PLT_GenericErrorReply  0
#define OseGW_PLT_InterfaceRequest   1
#define OseGW_PLT_InterfaceReply     2
#define OseGW_PLT_LoginRequest       3
#define OseGW_PLT_ChallengeResponse  4
#define OseGW_PLT_ChallengeReply     5
#define OseGW_PLT_LoginReply         6
#define OseGW_PLT_CreateRequest      7
#define OseGW_PLT_CreateReply        8
#define OseGW_PLT_DestroyRequest     9
#define OseGW_PLT_DestroyReply      10
#define OseGW_PLT_SendRequest       11
#define OseGW_PLT_SendReply         12
#define OseGW_PLT_ReceiveRequest    13
#define OseGW_PLT_ReceiveReply      14
#define OseGW_PLT_HuntRequest       15
#define OseGW_PLT_HuntReply         16
#define OseGW_PLT_AttachRequest     17
#define OseGW_PLT_AttachReply       18
#define OseGW_PLT_DetachRequest     19
#define OseGW_PLT_DetachReply       20
#define OseGW_PLT_NameRequest       21
#define OseGW_PLT_NameReply         22
#define OseGW_PLT_LAST_ENTRY        OseGW_PLT_NameReply

/* Authentication schemes */
#define OseGW_AUT_NoPassWord         0
#define OseGW_AUT_PlainText          1

/* Client interface flags. */
#define OseGw_CFL_LittleEndian 0x00000001

/* Server interface flags. */
#define OseGw_SFL_LittleEndian 0x00000001
#define OseGw_SFL_UseAuthent   0x00000002

/*
**********************************************************************
** Broadcast signal to check for OSE GateWays.
*/

struct OseGW_FindGW
{
   char str[1];
};

/*
** Answer signal from an OSE GateWay.
*/

struct OseGW_FoundGW
{
   char str[1];
};

/*
**********************************************************************
** Handle interface questions.
**
*/

struct OseGW_InterfaceRequest
{
   OseGW_UL cli_version; /* Client protocol version. */
   OseGW_UL cli_flags;
};

struct OseGW_InterfaceReply
{
   OseGW_UL status;
   OseGW_UL srv_version; /* Server protocol version. */
   OseGW_UL srv_flags;
   OseGW_UL types_len;
   OseGW_UL payload_types[1];
};

/*
**********************************************************************
** User authentication to get access to an OSE Gateway server.
**
** Challenge-response algorithm. It works like this: 
** Ps is the password stored on the server 
** Pc is the password entered by the client 
** H is a hash-function (md5 for example) 
** V is a 'random' value 
** 				   
** Server calculates H(V + Ps) and save this in a session
** variable. The server then send V to the client which respond with
** H(V + Pc). Now, the server can compare H(V + Ps) with H(V + Pc). If
** they are equal, the user must have given the correct password!
** Otherwise the identification failed.
*/

struct OseGW_LoginRequest
{
   OseGW_UL auth_type;
   char user_name[1];    /* Zero-terminated string of actual length. */
};

struct OseGW_ChallengeReply
{
   OseGW_UL status;
   OseGW_UL auth_type;
   OseGW_UL data_len;
   char     data[1];
};

struct OseGW_ChallengeResponse
{
   OseGW_UL data_len;
   char     data[1];
};

struct OseGW_LoginReply
{
   OseGW_UL status;
};

/*
**********************************************************************
** Create an OSE process handle.
**
*/

struct OseGW_CreateRequest
{
   OseGW_UL user;
   char     my_name[1];	 /* Zero-terminated string of actual length. */
};

/*
** Create handle reply signal.
*/

struct OseGW_CreateReply
{
   OseGW_UL status;
   OseGW_UL pid;
   OseGW_UL max_sigsize;
};

/*
**********************************************************************
** Destroy an OSE process handle.
*/

struct OseGW_DestroyRequest
{
   OseGW_UL pid;
};

/*
** Destroy reply.
*/

struct OseGW_DestroyReply
{
   OseGW_UL status;
};

/*
**********************************************************************
** Request to send an OSE signal.
*/

struct OseGW_SendRequest
{
   OseGW_UL from_pid;
   OseGW_UL dest_pid;
   OseGW_UL sig_len;
   OseGW_UL sig_no;
   char     sig_data[1];
};

/*
** Send reply.
*/

struct OseGW_SendReply
{
   OseGW_UL status;
};

/*
**********************************************************************
** Request to receive an OSE signal.
*/

struct OseGW_ReceiveRequest
{
   OseGW_UL timeout;
   OseGW_UL sigsel_len;
   OseGW_UL sigsel_list[1];
};

/*
** Receive reply.
*/

struct OseGW_ReceiveReply
{
   OseGW_UL status;
   OseGW_UL sender_pid;
   OseGW_UL addressee_pid;
   OseGW_UL sig_len;
   OseGW_UL sig_no;
   char     sig_data[1];
};

/*
**********************************************************************
** Hunt for an OSE process.
*/

struct OseGW_HuntRequest
{
   OseGW_UL user;
   OseGW_UL name_index;
   OseGW_UL sig_index;
   OseGW_UL sig_len;
   OseGW_UL sig_no;
   char     data[1];
};

/*
** Hunt reply.
*/

struct OseGW_HuntReply
{
   OseGW_UL status;
   OseGW_UL pid;
};

/*
**********************************************************************
** Attach to an OSE process.
*/

struct OseGW_AttachRequest
{
   OseGW_UL pid;
   OseGW_UL sig_len;
   OseGW_UL sig_no;
   char     sig_data[1];
};

/*
** Attach reply.
*/

struct OseGW_AttachReply
{
   OseGW_UL status;
   OseGW_UL attref;
};

/*
**********************************************************************
** Detach from an OSE process.
*/

struct OseGW_DetachRequest
{
   OseGW_UL attref;
};

/*
** Detach reply.
*/

struct OseGW_DetachReply
{
   OseGW_UL status;
};

/*
**********************************************************************
** Handle gateway server name query. Optional protocol packet.
**
*/

struct OseGW_NameRequest
{
   OseGW_UL reserved; /* Not used. */
};

struct OseGW_NameReply
{
   OseGW_UL status;
   OseGW_UL name_len; /* Length of name including terminating zero character. */
   char     name[1];  /* Zero-terminated string of actual length. */
};

/*
**********************************************************************
** TransportData
*/

struct OseGW_TransportHdr
{
   OseGW_UL payload_type;
   OseGW_UL payload_len;
};

struct OseGW_TransportData
{
   struct OseGW_TransportHdr         hdr;
   union
   {
      OseGW_UL                       start_of_payload;
      OseGW_UL                       status;
      struct OseGW_InterfaceRequest  interface_request;
      struct OseGW_InterfaceReply    interface_reply;
      struct OseGW_LoginRequest      login_request;
      struct OseGW_LoginReply        login_reply;
      struct OseGW_ChallengeResponse challenge_response;
      struct OseGW_ChallengeReply    challenge_reply;
      struct OseGW_CreateRequest     create_request;
      struct OseGW_CreateReply       create_reply;   
      struct OseGW_DestroyRequest    destroy_request;
      struct OseGW_DestroyReply      destroy_reply;  
      struct OseGW_SendRequest       send_request;   
      struct OseGW_SendReply         send_reply;     
      struct OseGW_ReceiveRequest    receive_request;
      struct OseGW_ReceiveReply      receive_reply;
      struct OseGW_HuntRequest       hunt_request;   
      struct OseGW_HuntReply         hunt_reply;     
      struct OseGW_AttachRequest     attach_request; 
      struct OseGW_AttachReply       attach_reply;   
      struct OseGW_DetachRequest     detach_request; 
      struct OseGW_DetachReply       detach_reply;
      struct OseGW_NameRequest       name_request;
      struct OseGW_NameReply         name_reply;
   } payload;
};

#endif
