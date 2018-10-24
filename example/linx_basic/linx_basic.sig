/*
 * Copyright (C) 2006-2009 by Enea Software AB.
 * All rights reserved.
 *
 * This Example is furnished under a Software License Agreement and
 * may be used only in accordance with the terms of such agreement.
 * No title to and ownership of the Example is hereby transferred.
 *
 * The information in this Example is subject to change
 * without notice and should not be construed as a commitment
 * by Enea Software AB.
 *
 * DISCLAIMER
 * This Example is delivered "AS IS", consequently 
 * Enea Software AB makes no representations or warranties, 
 * expressed or implied, for the Example. 
 */

#include <linx.h>

/*
 *    LINX example signal definitions.
 */

#define REQUEST_SIG 0x3340
struct request_sig {
      LINX_SIGSELECT sig_no;
      int            seqno;
};

#define REPLY_SIG   0x3341
struct reply_sig {
      LINX_SIGSELECT sig_no;
      int            seqno;
};

union LINX_SIGNAL {
      LINX_SIGSELECT     sig_no;
      struct request_sig request;
      struct reply_sig   reply;
};

