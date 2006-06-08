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
 * along with this library; if not, print to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef MQO_PROGRAM_H
#define MQO_PROGRAM_H 1

#include "mosvm.h"
#include <string.h>

mqo_integer mqo_instruction_code( mqo_primitive prim ){
    //TODO: This should be in the prim, along with uses_a, uses_b.
    mqo_integer i;
    for( i = 0; i <= mqo_max_opcode; i ++ ){
        if( mqo_instr_table[i] == prim ) break;
    }
    return i;
}

void mqo_format_instruction( mqo_string buf, mqo_instruction instr ){
    mqo_primitive prim = instr->prim;
    mqo_value a = instr->a;
    mqo_value b = instr->b;
    mqo_integer c = mqo_instruction_code( prim );
    
    mqo_string_append_byte( buf, '(' );
    mqo_string_append_sym( buf, mqo_prim_name( prim ) );

    if( prim->a ){
        mqo_string_append_byte( buf, ' ' );
        if( ! mqo_format_item( buf, instr->a ) )goto done;
    }

    if( prim->b ){
        mqo_string_append_byte( buf, ' ' );
        mqo_format_item( buf, instr->b );
    }
done:
    mqo_string_append_byte( buf, ')' );
}
mqo_procedure mqo_make_procedure( mqo_word length ){
    size_t tail = sizeof( struct mqo_instruction_data ) * length;
    mqo_procedure v = MQO_OBJALLOC2( procedure, tail );

    v->length = length;
    
    while( length ) v->inst[ -- length ].proc = v;

    return v;
}
void mqo_trace_procedure( mqo_procedure proc ){
    mqo_word i;
    for( i = 0; i < proc->length; i ++ ){
        mqo_word ct = 5; 
        mqo_instruction instr = mqo_procedure_ref( proc, i );
        mqo_grey_obj( (mqo_object) instr->prim );
        mqo_grey_val( instr->a );
        mqo_grey_val( instr->b );
    }
}

MQO_GENERIC_FORMAT( procedure );
MQO_GENERIC_COMPARE( procedure );
MQO_GENERIC_FREE( procedure );

MQO_C_TYPE( procedure );

MQO_BEGIN_PRIM( "assemble", assemble )
    REQ_LIST_ARG( source );
    NO_REST_ARGS( );
    PROCEDURE_RESULT( mqo_assemble( source ) );
MQO_END_PRIM( assemble )

void mqo_init_procedure_subsystem( ){
    MQO_I_TYPE( procedure );
    MQO_BIND_PRIM( assemble );
}

mqo_procedure mqo_assemble( mqo_list src ){
    mqo_integer index;
    mqo_pair p;
    mqo_primitive op;
    mqo_dict labels = mqo_make_dict( );
    index = 0; p = src;
    
    mqo_value parse_arg( mqo_value arg ){
        if( mqo_is_symbol( arg ) ){
            mqo_node node = mqo_tree_lookup( labels, arg );
            if( node )return mqo_cdr( mqo_pair_fv( node->data ) );
        };
        return arg;
    }

    while( p ){
        mqo_value line = mqo_car( p );

        if( mqo_is_pair( line ) ){
            mqo_pair l = mqo_pair_fv( line );
            index += 1;
            op = mqo_lookup_op( mqo_req_symbol( mqo_car( l ) ) );
            if( ! op ){ mqo_errf( mqo_es_vm, "sx", "unrecognized operator", l ); };
            mqo_integer len = mqo_list_length( l );
            if( len < 1 + op->a + op->b ){
                mqo_errf( mqo_es_vm, "sxi", "insufficent operands", op, len );
            }
        }else if( mqo_is_symbol( line ) ){
            mqo_tree_insert( 
                labels, mqo_vf_pair(
                    mqo_cons( line, mqo_vf_integer( index ) ) ) );
        }else{
            mqo_errf( mqo_es_vm, "s", "assemble requires a list of statements");
        };

        p = mqo_req_list( mqo_cdr( p ) );
    };
   
    if( ! index )mqo_errf( mqo_es_vm, "s", "empty source" );

    mqo_procedure proc = mqo_make_procedure( index );

    index = 0; p = src;

    while( p ){
        mqo_value line = mqo_car( p );

        if( mqo_is_pair( line ) ){
            mqo_pair l = mqo_pair_fv( line );
            op = mqo_lookup_op( mqo_symbol_fv( mqo_car( l ) ) );
            l = mqo_list_fv( mqo_cdr( l ) );
            proc->inst[index].prim = op;
            if( op->a ){
                proc->inst[index].a = parse_arg( mqo_car( l ) );
                l = mqo_list_fv( mqo_cdr( l ) );
            };
            if( op->b ){
                proc->inst[index].b = parse_arg( mqo_car( l ) );
            };
            index += 1;
        };

        p = mqo_req_list( mqo_cdr( p ) );
    };

    return proc;
}
#endif
