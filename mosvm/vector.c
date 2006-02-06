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

void mqo_show_vector( mqo_vector v, mqo_word* ct ){
    if( ! v )mqo_show_unknown( mqo_vector_type, 0 );

    mqo_integer ln = mqo_vector_length( v );
    mqo_integer ix = 0;
    
    mqo_writech( '#' );
    mqo_writeint( ln );
    mqo_writech( '(' );
    
    for( ix = 0; ix < ln; ix ++ ){
        if( ct ){
	    if( ! *ct ){
	        mqo_write( " ..." ); 
                goto done;
	    }
	
            (*ct)--;
        }

        mqo_space();
        mqo_show( mqo_vector_get( v, ix), ct );
    }
    
done:
    mqo_write( " )" );
} 
mqo_vector mqo_make_vector( mqo_integer length ){
    size_t tail = sizeof( mqo_value ) * length;
    mqo_vector v = MQO_ALLOC( mqo_vector, tail );

    v->length = length;
    memset( v->data, 0,  tail );
    return v;
}
mqo_vector mqo_copy_vector( mqo_vector vo, mqo_integer ln ){
    mqo_vector vn = mqo_make_vector( ln );
    while( ln-- ){
        mqo_vector_put( vn, ln, mqo_vector_get( vo, ln ) );
    }
    return vn;
}
mqo_boolean mqo_eqvv( mqo_vector a, mqo_vector b ){
    mqo_integer i;
    mqo_integer l = mqo_vector_length( a );
    if( l != mqo_vector_length( b ) )return 0;
    for( i = 0; i < l; i++ ){
        if( ! mqo_eq( mqo_vector_get( a, i ),
                      mqo_vector_get( b, i ) ) )return 0;
    }
    return 1;
}

mqo_boolean mqo_equalv( mqo_vector a, mqo_vector b ){
    mqo_integer i;
    mqo_integer l = mqo_vector_length( a );
    if( l != mqo_vector_length( b ) )return 0;
    for( i = 0; i < l; i++ ){
        if( ! mqo_equal( mqo_vector_get( a, i ),
                         mqo_vector_get( b, i ) ) )return 0;
    }
    return 1;
}
