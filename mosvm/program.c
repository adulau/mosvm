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

#ifndef MQO_PROGRAM_H
#define MQO_PROGRAM_H 1

#include "mosvm.h"
#include <string.h>

void mqo_show_instruction( mqo_instruction i, mqo_word* ct ){
    struct mqo_op_row* op = mqo_op_table + i->code;

    mqo_write( op->name );
    mqo_write( "(" );

    if( op->use_sy ){
        mqo_space( ); 
        mqo_writesym( i->sy );
    }else if( op->use_va ){
        mqo_space( );
        mqo_show( i->va, ct );
    }else if( op->use_w1 ){
        mqo_space( );
        mqo_writeint( i->w.a );
        if( op->use_w2 ){
            mqo_space( );
            mqo_writeint( i->w.b );
        }
    }
    mqo_write( " )" );
}

void mqo_dump_program( mqo_program p ){
    for( mqo_integer i = 0; i < p->length; i ++ ){
        mqo_word ct = 5; mqo_show_instruction( p->inst + i, &ct );
        mqo_newline( );
    }
}
mqo_program mqo_make_program( mqo_integer length ){
    size_t tail = sizeof( struct mqo_instruction_data ) * length;
    mqo_program v = MQO_ALLOC( mqo_program, tail );

    v->length = length;
    memset( v->inst, 0, tail );
    return v;
}
mqo_instruction mqo_program_ref( mqo_program program, mqo_integer index ){
    assert( program->length > index );
    return program->inst + index;
}

#endif
