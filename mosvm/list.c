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
#include <stdarg.h>

mqo_pair mqo_make_pair( ){
    return MQO_OBJALLOC( pair );
}
mqo_tc mqo_make_tc( ){
    mqo_tc tc = (mqo_tc)mqo_objalloc( mqo_tc_type,
                                      sizeof( struct mqo_pair_data ) );
    return tc;
}
mqo_pair mqo_cons( mqo_value car, mqo_value cdr ){
    mqo_pair c = mqo_make_pair( );
    mqo_set_car( c, car );
    mqo_set_cdr( c, cdr );
    return c;    
}
void mqo_tc_append( mqo_pair tc, mqo_value v ){
    mqo_pair it = mqo_cons( v, mqo_vf_null() );
    mqo_value pv = mqo_cdr( tc );
    
    if( mqo_is_pair( pv ) ){
	mqo_set_cdr( mqo_pair_fv( pv ), mqo_vf_pair( it ) );
    }else{
	mqo_set_car( tc, mqo_vf_pair( it ) );
    }
    
    mqo_set_cdr( tc, mqo_vf_pair( it ) );
}
mqo_pair mqo_list_ref( mqo_pair p, mqo_integer offset ){
    while( p && offset ){
        offset--; 
        p = mqo_req_list( mqo_cdr( p ) );
    }
    return p;
}

mqo_integer mqo_list_length( mqo_list p ){
    //TODO: Does not handle circular lists.
    mqo_integer c = 0;
    while( p ){
        c += 1;
        p = mqo_req_list( mqo_cdr( p ) );
    }
done:
    return c;
}
mqo_pair mqo_last_pair( mqo_pair p ){
    //TODO: Does not handle circular lists.
    if( ! p ){ goto done; }
    for(;;){
        mqo_value v = mqo_cdr( p );
        if( ! mqo_is_pair( v ) ){
            goto done;
        }else{
            p = mqo_pair_fv( v );
        };
    }
done:
    return p;
}

void mqo_trace_pair( mqo_pair p ){
    mqo_grey_val( mqo_car( p ) );
    mqo_grey_val( mqo_cdr( p ) );
}

void mqo_format_items( void* bbuf, mqo_pair p, mqo_boolean sp ){
    mqo_string buf = bbuf;
    if( p == NULL )return;
    
    for(;;){
        mqo_value car = mqo_car( p );
        mqo_value cdr = mqo_cdr( p );
    
        if( sp )mqo_format_char( buf, ' ' );
        sp = 1;
        mqo_format( buf, car );

        if( mqo_is_null( cdr ) ){
            return;
        }else if( mqo_is_pair( cdr ) ){
            p = mqo_pair_fv( cdr );
        }else{
            mqo_format_cs( buf, " . " );
            mqo_format( buf, cdr );
            return;
        }
    }
}
mqo_pair mqo_listf( mqo_integer ct, ... ){
    va_list ap;
    mqo_pair head = NULL;
    mqo_pair tail = NULL;
    mqo_pair item = NULL;

    va_start( ap, ct );
    while( ct -- ){
        mqo_value value = va_arg( ap, mqo_value );
                
        item = mqo_cons( value, mqo_vf_null( ) );

        if( tail ){
            mqo_set_cdr( tail, mqo_vf_pair( item ) );
        }else{
            head = item;
        };
        tail = item;
    }
done:
    va_end( ap );
    return head;
}

void mqo_format_pair( void* bbuf, mqo_pair p ){
    mqo_string buf = bbuf;
    mqo_format_char( buf, '(' );
    if( p ){
        mqo_format_items( buf, p, 0 );
    }
    mqo_format_char( buf, ')' );
}

MQO_GENERIC_FREE( pair );
MQO_GENERIC_COMPARE( pair );
MQO_C_TYPE( pair );
MQO_C_SUBTYPE( tc, pair );

// A very complicated and sophisticated primitive..
MQO_BEGIN_PRIM( "list", list )
    REST_ARGS( items )
    LIST_RESULT( items )
MQO_END_PRIM( list )

void mqo_init_list_subsystem( ){
    MQO_I_TYPE( pair );
    MQO_I_SUBTYPE( tc, pair );
    MQO_BIND_PRIM( list );
}
