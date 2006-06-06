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

#ifndef MQO_STREAM_H
#define MQO_STREAM_H 1

#include "memory.h"

mqo_value mqo_the_eof;

#define MQO_READY      0
#define MQO_CONNECTING 1
#define MQO_CLOSED     2 

MQO_BEGIN_TYPE( stream )
    mqo_integer fd;
    mqo_channel cmd, evt;
    mqo_stream prev, next;
    mqo_integer state, enabled;
    int error;
MQO_END_TYPE( stream )

MQO_BEGIN_TYPE( listener )
    mqo_integer fd;
    mqo_channel conns;
    mqo_listener prev, next;
    int error;
MQO_END_TYPE( listener )

MQO_H_TP( eof );
MQO_H_IS( eof );
static inline mqo_value mqo_vf_eof( ){ return mqo_the_eof; }

mqo_stream mqo_make_stream( mqo_integer fd );
mqo_listener mqo_make_listener( mqo_integer fd );
void mqo_init_stream_subsystem( );

mqo_channel mqo_stream_input( mqo_stream s );
mqo_channel mqo_stream_output( mqo_stream s );
void mqo_set_stream_input( mqo_stream s, mqo_channel c );
void mqo_set_stream_output( mqo_stream s, mqo_channel c );
static inline mqo_channel mqo_listener_output( mqo_listener s ){ return s->conns; }
static inline void mqo_set_listener_input( mqo_listener s, mqo_channel c ){ s->conns = c; }
#define REQ_STREAM_ARG( vn  ) REQ_TYPED_ARG( vn, stream );
#define OPT_STREAM_ARG( vn  ) OPT_TYPED_ARG( vn, stream );
#define STREAM_RESULT( x  ) TYPED_RESULT( stream, x );

#define REQ_LISTENER_ARG( vn  ) REQ_TYPED_ARG( vn, listener );
#define OPT_LISTENER_ARG( vn  ) OPT_TYPED_ARG( vn, listener );
#define LISTENER_RESULT( x  ) TYPED_RESULT( listener, x );

void mqo_enable_stream( mqo_stream s );
void mqo_disable_stream( mqo_stream s );
void mqo_trace_network();
extern mqo_stream mqo_stdio;

#endif
