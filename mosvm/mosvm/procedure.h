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

#ifndef MQO_PROCEDURE_H
#define MQO_PROCEDURE_H 1

#include "memory.h"

extern struct mqo_op_row mqo_op_table[];

struct mqo_procedure_data;
typedef struct mqo_procedure_data* mqo_procedure_x;

struct mqo_instruction_data {
    // Each instruction in the procedure refers to the procedure object; this
    // permits a closures and the virtual machine to not bother with managing
    // both a procedure pointer and an instruction pointer.

    mqo_procedure_x proc;
    mqo_primitive  prim;
    mqo_value a;
    mqo_value b;
}; 
typedef struct mqo_instruction_data* mqo_instruction;

MQO_BEGIN_TYPE( procedure )
    mqo_word length;
    struct mqo_instruction_data inst[0];
MQO_END_TYPE( procedure )
#define REQ_PROCEDURE_ARG( vn ) REQ_TYPED_ARG( vn, procedure )
#define PROCEDURE_RESULT( vn ) TYPED_RESULT( procedure, vn )
#define OPT_PROCEDURE_ARG( vn ) OPT_TYPED_ARG( vn, procedure )

mqo_procedure mqo_make_procedure( mqo_word length );
void mqo_dump_procedure( mqo_procedure procedure );
mqo_procedure mqo_assemble( mqo_pair source );

static inline mqo_instruction mqo_procedure_ref( 
    mqo_procedure procedure, mqo_word index 
){ 
    assert( index < procedure->length ); return procedure->inst + index; 
}

static inline mqo_word mqo_procedure_set(
    mqo_procedure procedure, mqo_word index, mqo_primitive prim, 
    mqo_value a, mqo_value b 
){
    mqo_instruction instr = mqo_procedure_ref( procedure, index );
    instr->prim = prim;
    instr->a = a;
    instr->b = b;
}

void mqo_format_instruction( mqo_string buf, mqo_instruction x );

void mqo_init_procedure_subsystem( );

#endif
