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

#ifndef MQO_VM_H
#define MQO_VM_H 1

#include "memory.h"
#include "primitive.h"
#include <setjmp.h>

MQO_BEGIN_TYPE( callframe )
    mqo_callframe   ap, cp;
    mqo_pair        ep;
    mqo_instruction ip;
    mqo_word        count;
    mqo_pair        head, tail;
MQO_END_TYPE( callframe )

mqo_callframe mqo_make_callframe( );

extern mqo_callframe   MQO_AP;
extern mqo_callframe   MQO_CP;
extern mqo_pair        MQO_EP;
extern mqo_pair        MQO_GP;
extern mqo_instruction MQO_IP;
extern mqo_value       MQO_RX;
extern mqo_integer mqo_trace_flag;

extern mqo_primitive mqo_instr_table[];
extern mqo_boolean mqo_uses_a[];
extern mqo_boolean mqo_uses_b[];
extern mqo_byte mqo_max_opcode;

void mqo_inner_exec( );
void mqo_outer_exec( );

void mqo_trace_registers();
void mqo_init_vm_subsystem( );

extern mqo_symbol mqo_es_vm;

jmp_buf* mqo_interp_xp;
jmp_buf* mqo_proc_xp;

void mqo_chain( mqo_pair data );
void mqo_chainf( mqo_value fn, mqo_word ct, ... );
void mqo_interp_loop( );

mqo_primitive mqo_lookup_op( mqo_symbol name );
mqo_value mqo_req_function( mqo_value v );
mqo_value mqo_reduce_function( mqo_value fn, mqo_list args );
#endif 
