/* Copyright (C) 2006, Ephemeral Security, LLC
 *
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Lesser General Public License, version 2.1
 * as published by the Free Software Foundation.
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
 * for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License 
 * along with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef MQO_CHANNEL_H
#define MQO_CHANNEL_H 1

#include "memory.h"

// A channel is a discrete channel of communication from one process to 
// another; they are often used for synchronization.
//
// A process may monitor zero or more channels.
// A process monitoring one or more channels is disabled until one of its
// channels gains a message.
// A message may be added to a channel at any time.

MQO_BEGIN_TYPE( channel )
    mqo_process monitor;
    mqo_pair    head, tail;
    mqo_integer length;
    mqo_channel prev, next;
MQO_END_TYPE( channel )

void mqo_add_monitor( mqo_process process, mqo_channel channel );
void mqo_remove_monitor( mqo_process process, mqo_channel channel );
void mqo_clear_monitors( mqo_process process );
void mqo_channel_append( mqo_channel channel, mqo_value message );
void mqo_channel_prepend( mqo_channel channel, mqo_value message );
mqo_boolean mqo_channel_empty( mqo_channel channel );
mqo_value mqo_channel_head( mqo_channel channel );
mqo_value mqo_channel_tail( mqo_channel channel );
mqo_value mqo_read_channel( mqo_channel channel );
mqo_channel mqo_make_channel( );

mqo_channel mqo_req_input( mqo_value x );
mqo_channel mqo_req_output( mqo_value x );

#define REQ_CHANNEL_ARG( x ) REQ_TYPED_ARG( x, channel )
#define OPT_CHANNEL_ARG( x ) OPT_TYPED_ARG( x, channel )
#define CHANNEL_RESULT( x )  TYPED_RESULT( channel, x )

#define REQ_INPUT_ARG( x )  mqo_channel x = mqo_req_input( mqo_req_any() );
#define REQ_OUTPUT_ARG( x )  mqo_channel x = mqo_req_output( mqo_req_any() );

void mqo_init_channel_subsystem( );

#endif
