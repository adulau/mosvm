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

#ifndef MQO_TIMEOUT_H
#define MQO_TIMEOUT_H 1

#include "memory.h"

MQO_BEGIN_TYPE( timeout )
    mqo_quad secs, nsecs;
    mqo_channel channel;
    mqo_value   signal;
    mqo_timeout prev, next;
MQO_END_TYPE( timeout )

mqo_timeout mqo_make_timeout( 
    mqo_quad ms, mqo_channel channel, mqo_value signal  
);

void mqo_trace_timeouts();
void mqo_init_time_subsystem( );
int mqo_any_timeouts();

#define REQ_TIMEOUT_ARG( x ) REQ_TYPED_ARG( x, timeout )
#define OPT_TIMEOUT_ARG( x ) OPT_TYPED_ARG( x, timeout )
#define TIMEOUT_RESULT( x )  TYPED_RESULT( timeout, x )

#endif
