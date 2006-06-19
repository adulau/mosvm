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

#include "mosvm.h"
#include <string.h>

#define MQO_MIN_VECTOR_LEN 64
#define MQO_MIN_VECTOR_SZ ( sizeof( struct mqo_vector_data ) + 64 * sizeof( mqo_value ) ) 

struct mqo_pool_data mqo_vector_scrap_data;
mqo_pool mqo_vector_scrap = &mqo_vector_scrap_data;

mqo_vector mqo_make_vector( mqo_integer length ){
    mqo_vector v;
    size_t tail = sizeof( mqo_value ) * length;
    
    if( length <= MQO_MIN_VECTOR_LEN ){
        v = (mqo_vector) mqo_scavenge( mqo_vector_type, mqo_vector_scrap, MQO_MIN_VECTOR_SZ );
    }else{
        v = MQO_OBJALLOC2( vector, tail );
    }

    v->length = length;
    return v;
}

void mqo_format_vector_items( mqo_string s, mqo_vector v, mqo_boolean sp ){
    mqo_integer ln = mqo_vector_length( v );
    mqo_integer ix = 0;

    for( ix = 0; ix < ln; ix ++ ){
        if( sp ) mqo_string_append_byte( s, ' ' );
        sp = 1;
        if( ! mqo_format_item( s, mqo_vector_get( v, ix ) ) )break;
    }
}
void mqo_format_vector( mqo_string s, mqo_vector v ){
    mqo_format_begin( s, v );
    mqo_format_vector_items( s, v, 1 ); 
    mqo_format_end( s );
}

mqo_vector mqo_copy_vector( mqo_vector vo, mqo_integer ln ){
    mqo_vector vn = mqo_make_vector( ln );
    while( ln-- ){
        mqo_vector_put( vn, ln, mqo_vector_get( vo, ln ) );
    }
    return vn;
}

mqo_integer mqo_vector_compare( mqo_vector a, mqo_vector b ){
    mqo_integer al = mqo_vector_length( a );
    mqo_integer bl = mqo_vector_length( b );
    mqo_integer i, l = ( al > bl )? bl : al;

    for( i = 0; i < l; i ++ ){
        mqo_integer d = mqo_cmp_eq( mqo_vector_get( a, i ),
                                    mqo_vector_get( b, i ) );
        if( d )return d;
    };

    return bl - al;
}
void mqo_trace_vector( mqo_vector v ){
    int i, l = mqo_vector_length( v );

    for( i = 0; i < l; i ++ ){
        mqo_grey_val( mqo_vector_get( v, i ) );
    }
}

void mqo_free_vector( mqo_vector vector ){
    if( vector->length <= MQO_MIN_VECTOR_LEN ){
        mqo_discard( (mqo_object) vector, mqo_vector_scrap );
    }else{
        mqo_objfree( vector );
    }
}
MQO_C_TYPE( vector );

void mqo_init_vector_subsystem( ){
    MQO_I_TYPE( vector );
}

