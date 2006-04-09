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

void mqo_show_pair_contents( mqo_pair p, mqo_word* ct ){
    int show_item( mqo_value v ){
        if( ct ){
            if( ! *ct ){
                mqo_write( "..." );
                p = NULL;
                return 1;
            }

            (*ct)--;
        }
        
        mqo_show( v, ct );	
        return 0;
    }

    while( p ){
        mqo_value car = mqo_car( p );
        mqo_value cdr = mqo_cdr( p );
        if( show_item( car ) )return;

        if( mqo_is_pair( cdr ) ){
            p = mqo_pair_fv( cdr );
            if( p )mqo_space( );
        }else{
            mqo_write( " . " );
            if( show_item( cdr ) )return; 
            p = NULL;
        };
    }
}
void mqo_show_pair( mqo_pair p, mqo_word* ct ){
    mqo_write( "(" );
    mqo_show_pair_contents( p, ct );
    mqo_write( ")" );
}
void mqo_show_tc( mqo_tc t, mqo_word* ct ){
    if( ! t )return mqo_show_unknown( mqo_tc_type, 0 );

    if(mqo_is_empty( mqo_car( t ) )){
        mqo_write("[tc]");
    }else{
        mqo_write( "[tc " );
        if( ct && (! *ct ) ){
            mqo_write( "..." );
        }else{
            mqo_show_pair_contents( mqo_pair_fv( mqo_car( t ) ), ct );
        }
        mqo_write( "]" );
    }
}
mqo_pair mqo_cons( mqo_value car, mqo_value cdr ){
    mqo_pair c = MQO_ALLOC( mqo_pair, 0 );
    mqo_set_car( c, car );
    mqo_set_cdr( c, cdr );
    return c;    
}
void mqo_tc_append( mqo_pair tc, mqo_value v ){
    mqo_pair it = mqo_cons( v, mqo_vf_empty() );
    
    mqo_pair pv = mqo_pair_fv( mqo_cdr( tc ) );
    
    if( pv ){
	mqo_set_cdr( pv, mqo_vf_pair( it ) );
    }else{
	mqo_set_car( tc, mqo_vf_pair( it ) );
    }
    
    mqo_set_cdr( tc, mqo_vf_pair( it ) );
}

mqo_pair mqo_list_ref( mqo_pair p, mqo_integer offset ){
    while( p && offset ){
        offset--; 
        p = mqo_pair_fv( mqo_cdr( p ) );
    }
    return p;
}
mqo_tc mqo_make_tc( ){
    return (mqo_tc)mqo_cons( mqo_vf_empty(), mqo_vf_empty() );
}

mqo_boolean mqo_eqvp( mqo_pair a, mqo_pair b ){
    mqo_value av, bv;

    for(;;){
        if( !a )return !b;
        if( !b )return 0;

        if( !mqo_eq( mqo_car( a ), mqo_car ( b ) ) )return 0;
        av = mqo_cdr( a );
        bv = mqo_cdr( b );

        if( av.type != bv.type )return 0;
        if( av.type != mqo_pair_type )return av.data == bv.data;

        a = mqo_pair_fv( av );
        b = mqo_pair_fv( bv );
    }
    // We surrender! It's equal! It's equal!
    return 1;
}

mqo_boolean mqo_equalp( mqo_pair a, mqo_pair b ){
    mqo_value av, bv;

    for(;;){
        if( !a )return !b;
        if( !b )return 0;

        if( !mqo_equal( mqo_car( a ), mqo_car ( b ) ) )return 0;
        av = mqo_cdr( a );
        bv = mqo_cdr( b );

        if( av.type != mqo_pair_type )return mqo_equal( av, bv );
        if( av.type != bv.type )return 0;

        a = mqo_pair_fv( av );
        b = mqo_pair_fv( bv );
    }
    // We surrender! It's equal! It's equal!
    return 1;
}

mqo_pair mqo_last_pair( mqo_pair p ){
    //TODO: Does not handle circular lists.
    if( ! p ){ goto done; }
    for(;;){
        mqo_value v = mqo_cdr( p );
        if(( ! mqo_is_pair( v ) )|| mqo_is_empty( v )){
            goto done;
        }else{
            p = mqo_pair_fv( v );
        };
    }
done:
    return p;
}

mqo_pair mqo_req_list( mqo_value v, const char* s ){
    mqo_pair pair = mqo_req_pair( v, s );
    if( pair )return pair;
    mqo_errf( mqo_es_args, "ss", "expected non-empty list for", s ); 
}

