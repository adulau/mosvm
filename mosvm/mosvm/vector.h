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

#ifndef MQO_VECTOR_H
#define MQO_VECTOR_H 1

#include "memory.h"

MQO_BEGIN_TYPE( vector )
    mqo_word  length;
    mqo_value data[0];
MQO_END_TYPE( vector )
#define REQ_VECTOR_ARG( vn ) REQ_TYPED_ARG( vn, vector )
#define VECTOR_RESULT( vn ) TYPED_RESULT( vn, vector )
#define OPT_VECTOR_ARG( vn ) OPT_TYPED_ARG( vn, vector )

mqo_vector mqo_make_vector( mqo_integer length );
static inline mqo_integer mqo_vector_length( mqo_vector v ){ 
    return v->length; 
}
static inline mqo_value *mqo_vector_ref( mqo_vector v, mqo_integer offset ){
    assert( 0 <= offset );
    assert( offset < v->length ); 
    return v->data + offset;
}
static inline mqo_value mqo_vector_get( mqo_vector v, mqo_integer offset ){ 
    return *(mqo_vector_ref( v, offset )); 
}
static inline void mqo_vector_put( mqo_vector v, mqo_integer offset, 
                                   mqo_value x ){
    *(mqo_vector_ref( v, offset )) = x; 
}

mqo_vector mqo_copy_vector( mqo_vector vo, mqo_integer ln );

mqo_boolean mqo_eqvv( mqo_vector v1, mqo_vector v2 );
mqo_boolean mqo_equalv( mqo_vector v1, mqo_vector v2 );

void mqo_show_vector_contents( mqo_vector p, mqo_word* ct );
void mqo_show_vector( mqo_vector p, mqo_word* ct );

void mqo_init_vector_subsystem( );

#endif
