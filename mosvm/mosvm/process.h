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

#ifndef MQO_PROCESS_H
#define MQO_PROCESS_H 1

#include "memory.h"

typedef void (*mqo_proc_fn)(mqo_object process, mqo_value context );

MQO_BEGIN_TYPE( process )
    mqo_process prev, next;
    mqo_proc_fn activate, deactivate;
    mqo_value context;
    mqo_boolean enabled;
    mqo_object monitoring; //TODO: This is a channel..
    mqo_object input, output;
MQO_END_TYPE( process )

MQO_BEGIN_TYPE( vm )
    mqo_instruction ip;
    mqo_callframe   ap, cp;
    mqo_list        ep, gp;
    mqo_value       rx;
MQO_END_TYPE( vm )

mqo_process mqo_make_process( 
    mqo_proc_fn activate, mqo_proc_fn deactivate, mqo_value context 
);
void mqo_trace_process( mqo_process process );

mqo_vm mqo_make_vm( );
void mqo_trace_vm( mqo_vm vm );

void mqo_trace_actives( );

void mqo_enable_process( mqo_process process );
void mqo_disable_process( mqo_process process );

void mqo_proc_loop( );

mqo_process mqo_spawn_func( mqo_value func );

mqo_object mqo_process_input( mqo_process process );
mqo_object mqo_process_output( mqo_process process );
void mqo_set_process_input( mqo_process process, mqo_object input );
void mqo_set_process_output( mqo_process process, mqo_object output );
void mqo_init_process_subsystem( );

extern mqo_process mqo_active_process;

extern mqo_process mqo_first_enabled;
extern mqo_process mqo_last_enabled;
extern mqo_process mqo_active_process;

static inline mqo_boolean mqo_can_be_only_one( ){
    return ( mqo_active_process == mqo_first_enabled ) && 
           ( mqo_active_process == mqo_last_enabled );
}

#define REQ_PROCESS_ARG( x ) REQ_TYPED_ARG( x, process )
#define OPT_PROCESS_ARG( x ) OPT_TYPED_ARG( x, process )
#define PROCESS_RESULT( x )  TYPED_RESULT( process, x )

#endif
