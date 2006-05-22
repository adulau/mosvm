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

mqo_pair mqo_make_pair( ){
    return MQO_OBJALLOC( pair );
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
mqo_pair mqo_make_tc( ){
    return mqo_cons( mqo_vf_null(), mqo_vf_null() );
}

mqo_integer mqo_list_length( mqo_list p ){
    //TODO: Does not handle circular lists.
    mqo_integer c = 0;
    while( p ){
        c += 1;
        p = mqo_list_fv( mqo_cdr( p ) );
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

void mqo_show_list_contents( mqo_pair p, mqo_word* ct ){
    if( p == NULL )return;

    for(;;){
        mqo_value car = mqo_car( p );
        mqo_value cdr = mqo_cdr( p );

        if( *ct == 0 ){
            mqo_print( "..." );
            return;
        }

        mqo_show( car, ct );

        if( mqo_is_null( cdr ) ){
            return;
        }else if( mqo_is_pair( cdr ) ){
            mqo_space( );
            p = mqo_pair_fv( cdr );
        }else{
            mqo_print( " . " );
            mqo_show( cdr, ct );
            return;
        }
    }
}

void mqo_show_pair( mqo_pair p, mqo_word* ct ){
    mqo_print( "(" );
    mqo_show_list_contents( p, ct );
    mqo_print( ")" );
}

MQO_GENERIC_FREE( pair );
MQO_GENERIC_COMPARE( pair );
MQO_C_TYPE( pair );

void mqo_init_list_subsystem( ){
    MQO_I_TYPE( pair );
}
