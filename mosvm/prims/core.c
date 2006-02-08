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

#include "../mosvm.h"
#include "../mosvm/prim.h"
#include <string.h>
#include <unistd.h>
#include <sys/param.h>
#include <errno.h>

MQO_BEGIN_PRIM( "cadr", cadr )
    REQ_LIST_ARG( list )
    list = mqo_req_list( mqo_cdr( list ), "list" );
    MQO_RESULT( mqo_car(  list ) );
MQO_END_PRIM( cadr );

MQO_BEGIN_PRIM( "reverse", reverse )
    REQ_PAIR_ARG( pair );
    mqo_pair ep = NULL;
    mqo_pair next;
    while( pair ){
        ep = mqo_cons( mqo_car( pair ), mqo_vf_pair( ep ) );
        pair = mqo_req_pair( mqo_cdr( pair ), "pair-cdr" );
    }
    MQO_RESULT( mqo_vf_pair( ep ) );
MQO_END_PRIM( reverse );

MQO_BEGIN_PRIM( "reverse!", reversed )
    REQ_PAIR_ARG( pair );
    mqo_pair ep = NULL;
    mqo_pair next;
    while( pair ){
        next = mqo_req_pair( mqo_cdr( pair ), "pair-cdr" );
        mqo_set_cdr( pair, mqo_vf_pair( ep ) );
        ep = pair;
        pair = next;
    }
    MQO_RESULT( mqo_vf_pair( ep ) );
MQO_END_PRIM( reversed );

MQO_BEGIN_PRIM( "caddr", caddr )
    REQ_PAIR_ARG( pair )
    v_pair = mqo_cdr( pair );
    if(! mqo_is_pair( v_pair ) ){
        mqo_errf( mqo_es_args, "sx", "expected pair", v_pair );
    };
    if( mqo_is_empty( v_pair ) ){
        mqo_errf( mqo_es_args, "sx", "expected non-empty", v_pair );
    };
    v_pair = mqo_cdr( mqo_pair_fv( v_pair ) );
    if(! mqo_is_pair( v_pair ) ){
        mqo_errf( mqo_es_args, "sx", "expected pair", v_pair );
    };
    if( mqo_is_empty( v_pair ) ){
        mqo_errf( mqo_es_args, "sx", "expected non-empty", v_pair );
    };
    MQO_RESULT( mqo_car( mqo_pair_fv( v_pair ) ) );
MQO_END_PRIM( caddr );

MQO_BEGIN_PRIM( "equal?", equalq )
    REQ_VALUE_ARG( v0 );
    while( ai < ct ){
        REQ_VALUE_ARG( vN );
        if( ! mqo_equal( v0, vN ) ){
            MQO_RESULT( mqo_vf_false( ) );
        }
    }
    MQO_RESULT( mqo_vf_true( ) );
MQO_END_PRIM( equalq );

MQO_BEGIN_PRIM( "eqv?", eqvq )
    REQ_VALUE_ARG( v0 );
    while( ai < ct ){
        REQ_VALUE_ARG( vN );
        if( ! mqo_eqv( v0, vN ) ){
            MQO_RESULT( mqo_vf_false( ) );
        }
    }
    MQO_RESULT( mqo_vf_true( ) );
MQO_END_PRIM( eqvq );

MQO_BEGIN_PRIM( "string?", stringq )
    REQ_VALUE_ARG( value )
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_boolean( mqo_is_string( value ) ) );
MQO_END_PRIM( stringq )

MQO_BEGIN_PRIM( "symbol?", symbolq )
    REQ_VALUE_ARG( value )
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_boolean( mqo_is_symbol( value ) ) );
MQO_END_PRIM( symbolq )

MQO_BEGIN_PRIM( "not", not )
    REQ_VALUE_ARG( value )
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_boolean( mqo_is_false( value ) ) );
MQO_END_PRIM( not )

MQO_BEGIN_PRIM( "last-pair", last_pair )
    REQ_LIST_ARG( list )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_pair( mqo_last_pair( list ) ) ); 
MQO_END_PRIM( last_pair )

MQO_BEGIN_PRIM( "last-item", last_item )
    REQ_LIST_ARG( list )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_car( mqo_last_pair( list ) ) ); 
MQO_END_PRIM( last_item )

MQO_BEGIN_PRIM( "list-ref", list_ref )
    REQ_PAIR_ARG( list );
    REQ_INTEGER_ARG( index );
    NO_MORE_ARGS( );

    MQO_RESULT( mqo_car( mqo_list_ref( list, index ) ) );
MQO_END_PRIM( list_ref )

MQO_BEGIN_PRIM( "abs", m_abs )
    REQ_INTEGER_ARG( integer );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_integer( integer < 0 ?  -integer : integer ) );
MQO_END_PRIM( m_abs )

MQO_BEGIN_PRIM( "+", m_add )
    REQ_INTEGER_ARG( v0 );
    while( ai < ct ){
        REQ_INTEGER_ARG( vN );
        v0 += vN;
    };
    MQO_RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_add )

MQO_BEGIN_PRIM( "-", m_sub )
    REQ_INTEGER_ARG( v0 );
    if( ct == 1 ){
        MQO_RESULT( mqo_vf_integer( -v0 ) );
    }else{
        while( ai < ct ){
            REQ_INTEGER_ARG( vN );
            v0 -= vN;
        };
    }
    MQO_RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_sub )

MQO_BEGIN_PRIM( "*", m_mul )
    REQ_INTEGER_ARG( v0 );
    while( ai < ct ){
        REQ_INTEGER_ARG( vN );
        v0 *= vN;
    };
    MQO_RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_mul )

MQO_BEGIN_PRIM( "/", m_div )
    REQ_INTEGER_ARG( v0 );
    while( ai < ct ){
        REQ_INTEGER_ARG( vN );
        if(! vN ){
            mqo_errf( mqo_es_args, "s", "attempted divide by zero" );
        }
        v0 /= vN;
    };
    MQO_RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_div )

MQO_BEGIN_PRIM( "quotient", quotient )
    REQ_INTEGER_ARG( n1 );
    REQ_INTEGER_ARG( n2 );
    if(! n2 ){
        mqo_errf( mqo_es_args, "s", "attempted divide by zero" );
    }
    MQO_RESULT( mqo_vf_integer( n1 / n2 ) );
MQO_END_PRIM( quotient )

MQO_BEGIN_PRIM( "remainder", remainder )
    REQ_INTEGER_ARG( n1 );
    REQ_INTEGER_ARG( n2 );
    if(! n2 ){
        mqo_errf( mqo_es_args, "s", "attempted divide by zero" );
    }
    MQO_RESULT( mqo_vf_integer( n1 % n2 ) );
MQO_END_PRIM( remainder )

MQO_BEGIN_PRIM( "number->string", number_to_string )
    /* "Time they say is the great healer, but I believe in chemicals, baby."
     * -- Fatboy Slim, "Push and Shove" */

    /* There is precisely one way to output a number in base 10 in the standard
       C library. But I'll be damned if I'll use sprintf. */
    REQ_INTEGER_ARG( number );
    NO_MORE_ARGS( );

    static char buf[256];
    buf[255] = 0;
    int i = 255;
    int neg = number < 0;

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );

    if( neg )buf[ -- i ] = '-';

    MQO_RESULT( mqo_vf_string( mqo_string_fm( buf + i, 255 - i ) ) );
MQO_END_PRIM( number_to_string );

MQO_BEGIN_PRIM( "string->symbol", string_to_symbol )
    REQ_STRING_ARG( string );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_symbol( mqo_symbol_fs( mqo_sf_string( string ) ) ) );
MQO_END_PRIM( string_to_symbol );

MQO_BEGIN_PRIM( "symbol->string", symbol_to_string )
    REQ_SYMBOL_ARG( symbol );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_string( symbol->string ) );
MQO_END_PRIM( symbol_to_string );

MQO_BEGIN_PRIM( "make-vector", make_vector )
    REQ_INTEGER_ARG( length );
    OPT_VALUE_ARG( init );
    NO_MORE_ARGS( );
    mqo_vector v = mqo_make_vector( length );
    if( has_init ){
        while( length-- ){
            mqo_vector_put( v, length, init );
        }
    }
    MQO_RESULT( mqo_vf_vector( v ) );
MQO_END_PRIM( make_vector )

MQO_BEGIN_PRIM( "append", append )
    REST_ARGS( args );
    mqo_tc tc = mqo_make_tc();
    while( args ){
        mqo_pair it = mqo_req_pair( mqo_car( args ), "list" );

        while( it ){
            mqo_tc_append( tc, mqo_car( it ) );
            it = mqo_req_pair( mqo_cdr( it ), "list" );
        }
        args = mqo_pair_fv( mqo_cdr( args ) );               
    };
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( append )

MQO_BEGIN_PRIM( "append!", appendd )
    mqo_pair last = NULL;
    for( ai = ct; ai > 0; ai -- ){
        mqo_pair next = mqo_req_pair( mqo_vector_get( MQO_SV, 
                                                      MQO_SI + ai - ct - 2 ),
                                      "list" );
        if( next ){
            mqo_set_cdr( mqo_last_pair( next ), mqo_vf_pair( last ) );
            last = next;
        }
    }

    MQO_RESULT( mqo_vf_pair( last ) );
MQO_END_PRIM( appendd )

MQO_BEGIN_PRIM( "list-index", list_index )
    REQ_VALUE_ARG( item );
    REQ_PAIR_ARG( list );
    NO_MORE_ARGS( );
    mqo_integer ix = 0;

    while( list ){
        if( mqo_eq( mqo_car( list ), item ) ){
            MQO_RESULT( mqo_vf_integer( ix ) );
        }
        ix++;
        mqo_value v = mqo_cdr( list );
        if(!  mqo_is_pair( v ) ){
            MQO_NO_RESULT();
        };
        list = mqo_pair_fv( v );
    }
    MQO_NO_RESULT();
MQO_END_PRIM( list_index );

MQO_BEGIN_PRIM( "memq", memq )
    REQ_VALUE_ARG( item );
    REQ_PAIR_ARG( list );
    NO_MORE_ARGS( );
    while( list ){
        if( mqo_eq( item, mqo_car( list ) ) ){
            MQO_RESULT( mqo_vf_pair( list ) );
        }
        list = mqo_pair_fv( mqo_cdr( list ) );
    }
    MQO_RESULT( mqo_vf_false() );
MQO_END_PRIM( memq );

MQO_BEGIN_PRIM( "exit", exit )
    OPT_INTEGER_ARG( code );
    NO_MORE_ARGS( );
    exit( has_code ? code : 0 );
MQO_END_PRIM( exit )

const char* mqo_prim_apply_name = "apply";
void mqo_prim_apply( ){
    // The old weird bastard of the lisp world gets really hairy when
    // dealing with a data stack.

    mqo_integer ct = mqo_peek_int_ds();
    mqo_integer ai = 1;
    if( ct < 2 ){
        mqo_errf( mqo_es_vm, "s",
            "apply requires at least two arguments, a function and a"
            " list of arguments." 
        );
    }
    mqo_value v_tail = mqo_vector_get( MQO_SV, MQO_SI - 2 );
    if(! mqo_is_pair( v_tail ) ){
        mqo_errf( mqo_es_vm, "sx",
            "the last argument to apply must be a list.", v_tail
        );
    };
    mqo_pair tail = mqo_pair_fv( v_tail );
    mqo_value fn = mqo_vector_get( MQO_SV, MQO_SI - ct - 1 );
    if(!( mqo_is_function( fn )|| mqo_is_program( fn ) )){
        mqo_errf( mqo_es_vm, "sx",
            "the first argument to apply must be a function.", fn
        );
    }

    // That's the last of the errors we can raise, here. Now to chainsaw
    // the stack, and tail-call our way to glory!
    MQO_SI -= 1;

    // Count shall now reflect the number of applied arguments that are
    // on the stack.
    ct -= 2;

    // We now have to slide the applied arguments down over the 
    // function, using memmove.
    memmove( 
        mqo_vector_ref( MQO_SV, MQO_SI - ct - 2),
        mqo_vector_ref( MQO_SV, MQO_SI - ct - 1),
        ct * sizeof( mqo_value )
    );
   
    // Adjust the stack depth again to compensate for the lost function,
    // and crop the count off.
    MQO_SI -= 2;

    mqo_value next;
    // Now, for each value in the tail..
    while( tail != NULL ){
        mqo_push_ds( mqo_car( tail ) );
        ct ++;
        if( mqo_is_pair( next = mqo_cdr( tail ) ) ){
            tail = mqo_pair_fv( next );
        }else{
            // R5RS suggests we throw an error, but this is making
            // a long function even longer..
            mqo_push_ds( next ); 
            break;
        };
    }

    mqo_push_int_ds( ct );
    mqo_tail_call( fn );
}

MQO_BEGIN_PRIM( "eq?", eq )
    REQ_VALUE_ARG( v0 );
    while( ai < ct ){
        REQ_VALUE_ARG( vN );
        if( ! mqo_eq( v0, vN ) ){
            MQO_RESULT( mqo_vf_false( ) );
        }
    }
    MQO_RESULT( mqo_vf_true( ) );
MQO_END_PRIM( eq )

MQO_BEGIN_PRIM( "list?", listq )
    REQ_VALUE_ARG( v );
    NO_MORE_ARGS( );

    if( ! mqo_is_pair( v ) ){
        MQO_RESULT( mqo_vf_false() );
    }else{
        mqo_pair p0 = mqo_pair_fv( v );
        mqo_pair pN = p0;
        while( pN ){
            v = mqo_cdr( pN );
            if(! mqo_is_pair( v ) ){
                MQO_RESULT( mqo_vf_false() )
            }
            pN = mqo_pair_fv( v );
            if( pN == p0 ){
                MQO_RESULT( mqo_vf_false() )
            }
        }
    }
    
    MQO_RESULT( mqo_vf_true() );
MQO_END_PRIM( listq )

MQO_BEGIN_PRIM( "integer?", integerq )
    REQ_VALUE_ARG( v );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( ( mqo_is_integer( v ) ) ) );
MQO_END_PRIM( integerq )

MQO_BEGIN_PRIM( "pair?", pairq )
    REQ_VALUE_ARG( v );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( ( mqo_is_pair( v ) ) ) );
MQO_END_PRIM( pairq )

MQO_BEGIN_PRIM( "null?", nullq )
    REQ_VALUE_ARG( v );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( ( mqo_is_empty( v ) ) ) );
MQO_END_PRIM( nullq )

MQO_BEGIN_PRIM( "cons", cons )
    REQ_VALUE_ARG( car );
    REQ_VALUE_ARG( cdr );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_pair( mqo_cons( car, cdr ) ) );
MQO_END_PRIM( cons )

MQO_BEGIN_PRIM( "car", car )
    REQ_PAIR_ARG( p );
    NO_MORE_ARGS( );
    ERR_IF_NULL( p );
    MQO_RESULT( mqo_car( p ) );
MQO_END_PRIM( car )

MQO_BEGIN_PRIM( "cdr", cdr )
    REQ_PAIR_ARG( p );
    NO_MORE_ARGS( );
    ERR_IF_NULL( p );
    MQO_RESULT( mqo_cdr( p ) );
MQO_END_PRIM( cdr )

MQO_BEGIN_PRIM( "set-car!", set_car )
    REQ_PAIR_ARG( p );
    REQ_VALUE_ARG( car );
    NO_MORE_ARGS( );
    ERR_IF_NULL( p );
    mqo_set_car( p, car );
    MQO_NO_RESULT( );
MQO_END_PRIM( set_car )

MQO_BEGIN_PRIM( "set-cdr!", set_cdr )
    REQ_PAIR_ARG( p );
    REQ_VALUE_ARG( cdr );
    NO_MORE_ARGS( );
    ERR_IF_NULL( p );
    mqo_set_cdr( p, cdr );
    MQO_NO_RESULT( );
MQO_END_PRIM( set_cdr )

MQO_BEGIN_PRIM( "list", list )
    REST_ARGS( l );
    MQO_RESULT( mqo_vf_pair( l ) );
MQO_END_PRIM( list )

MQO_BEGIN_PRIM( "vector", vector )
    mqo_vector vt = mqo_make_vector( ct );
    memcpy( 
        mqo_vector_ref( vt, 0 ),
        mqo_vector_ref( MQO_SV, MQO_SI - ct - 1 ),
        ct * sizeof( mqo_value )
    );
    MQO_RESULT( mqo_vf_vector( vt ) );
MQO_END_PRIM( vector )

MQO_BEGIN_PRIM( "vector-ref", vector_ref )
    REQ_VECTOR_ARG( vector );
    REQ_INTEGER_ARG( index );
    NO_MORE_ARGS( );
    if( index < mqo_vector_length( vector ) ){
        MQO_RESULT( mqo_vector_get( vector, index ) );
    }else{
        mqo_errf( 
            mqo_es_vm,
            "sisi", 
            "index ", index, "greater than vector length", 
            mqo_vector_length( vector ) 
        );
        MQO_NO_RESULT( );
    }
MQO_END_PRIM( vector_ref )

MQO_BEGIN_PRIM( "vector-set!", vector_set )
    REQ_VECTOR_ARG( vector );
    REQ_INTEGER_ARG( index );
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    if( index < mqo_vector_length( vector ) ){
        mqo_vector_put( vector, index, value );
    }else{
        mqo_errf( 
            mqo_es_vm,
            "sisi", 
            "index ", index, "greater than vector length", 
            mqo_vector_length( vector ) 
        );
    };
    MQO_NO_RESULT( );
MQO_END_PRIM( vector_set )

MQO_BEGIN_PRIM( "vector-length", vector_length )
    REQ_VECTOR_ARG( vector );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_integer( mqo_vector_length( vector ) ) );
MQO_END_PRIM( vector_length )

MQO_BEGIN_PRIM( "string-length", string_length )
    REQ_STRING_ARG( string );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_integer( mqo_string_length( string ) ) );
MQO_END_PRIM( string_length )

MQO_BEGIN_PRIM( "string-ref", string_ref )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    NO_MORE_ARGS( );
    if( index >= mqo_string_length( string ) ){
        mqo_errf( mqo_es_args, "si", "index greater than string length", 
                               index );
    }
    MQO_RESULT( mqo_vf_integer( string->data[index] ) );
MQO_END_PRIM( string_ref )

MQO_BEGIN_PRIM( "=", m_eq )
    REQ_INTEGER_ARG( left );
    REQ_INTEGER_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( left == right ) );
MQO_END_PRIM( m_eq )

MQO_BEGIN_PRIM( "<", m_lt )
    REQ_INTEGER_ARG( left );
    REQ_INTEGER_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( left < right ) );
MQO_END_PRIM( m_lt )

MQO_BEGIN_PRIM( ">", m_gt )
    REQ_INTEGER_ARG( left );
    REQ_INTEGER_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( left > right ) );
MQO_END_PRIM( m_gt )

MQO_BEGIN_PRIM( "<=", m_lte )
    REQ_INTEGER_ARG( left );
    REQ_INTEGER_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( left <= right ) );
MQO_END_PRIM( m_lt )

MQO_BEGIN_PRIM( ">=", m_gte )
    REQ_INTEGER_ARG( left );
    REQ_INTEGER_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( left >= right ) );
MQO_END_PRIM( m_gte )

MQO_BEGIN_PRIM( "!=", m_ne )
    REQ_INTEGER_ARG( left );
    REQ_INTEGER_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( left != right ) );
MQO_END_PRIM( m_ne )

MQO_BEGIN_PRIM( "string=?", string_eqq )
    REQ_STRING_ARG( left );
    REQ_STRING_ARG( right );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_eqvs( left, right ) ) );
MQO_END_PRIM( string_eqq )

MQO_BEGIN_PRIM( "vector?", vectorq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_vector( value ) ) );
MQO_END_PRIM( vectorq )

MQO_BEGIN_PRIM( "length", length )
    REQ_PAIR_ARG( pair );
    NO_MORE_ARGS( );
    ai = 0;
    while( pair ){
        ai++;
        v_pair = mqo_cdr( pair );
        if( mqo_is_pair( v_pair ) ){
            pair = mqo_pair_fv( v_pair );
        }else{
            goto done;
        }
    }
done:
    MQO_RESULT( mqo_vf_integer( ai )  );
MQO_END_PRIM( length )

MQO_BEGIN_PRIM( "error", error )
    REQ_SYMBOL_ARG( key );
    REST_ARGS( info );
    NO_MORE_ARGS( );

    mqo_err( key, info );
MQO_END_PRIM( error )

MQO_BEGIN_PRIM( "show", show )
    REQ_VALUE_ARG( val );
    OPT_INTEGER_ARG( count );
    NO_MORE_ARGS( );
    
    mqo_word ict = count; mqo_show( val, has_count ? &ict : NULL );

    MQO_NO_RESULT( );
MQO_END_PRIM( show )

MQO_BEGIN_PRIM( "error?", errorq )
    REQ_VALUE_ARG( val );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_is_error( val ) ? mqo_vf_true( ) : mqo_vf_false( ) );
MQO_END_PRIM( errorq )

MQO_BEGIN_PRIM( "error-key", error_key )
    REQ_ERROR_ARG( err );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_symbol( err->key ) );
MQO_END_PRIM( error_key )

MQO_BEGIN_PRIM( "error-info", error_info )
    REQ_ERROR_ARG( err );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_pair( err->info ) );
MQO_END_PRIM( error_info )

MQO_BEGIN_PRIM( "error-state", error_state )
    REQ_ERROR_ARG( err );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_vmstate( err->state ) );
MQO_END_PRIM( error_state )

MQO_BEGIN_PRIM( "vmstate-ip", vmstate_ip )
    REQ_VMSTATE_ARG( vms );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_instruction( vms->ip ) );
MQO_END_PRIM( vmstate_ip )

MQO_BEGIN_PRIM( "vmstate-cp", vmstate_cp )
    REQ_VMSTATE_ARG( vms );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_program( vms->cp ) );
MQO_END_PRIM( vmstate_cp )

MQO_BEGIN_PRIM( "vmstate-sv", vmstate_sv )
    REQ_VMSTATE_ARG( vms );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_vector( vms->sv ) );
MQO_END_PRIM( vmstate_sv )

MQO_BEGIN_PRIM( "vmstate-rv", vmstate_rv )
    REQ_VMSTATE_ARG( vms );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_vector( vms->rv ) );
MQO_END_PRIM( vmstate_rv )

MQO_BEGIN_PRIM( "vmstate-ep", vmstate_ep )
    REQ_VMSTATE_ARG( vms );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_pair( vms->ep ) );
MQO_END_PRIM( vmstate_ep )

MQO_BEGIN_PRIM( "vmstate-gp", vmstate_gp )
    REQ_VMSTATE_ARG( vms );
    NO_MORE_ARGS( );
  
    MQO_RESULT( mqo_vf_pair( vms->gp ) );
MQO_END_PRIM( vmstate_gp )

MQO_BEGIN_PRIM( "il-traceback", il_traceback )
    REQ_ERROR_ARG( err );
    NO_MORE_ARGS( );
  
    mqo_il_traceback( err );

    MQO_NO_RESULT( );
MQO_END_PRIM( il_traceback )

MQO_BEGIN_PRIM( "map-car", map_car )
    REQ_PAIR_ARG( src );
    NO_MORE_ARGS( );
    mqo_tc tc = mqo_make_tc();
    while( src ){
        mqo_value v = mqo_car( src );
        if( mqo_is_pair( v ) ){
            mqo_tc_append( tc, mqo_car( mqo_pair_fv( v  ) ) );
        }else{
            mqo_errf( 
                mqo_es_args,
                "sx", "map-car requires that all members of the list be pairs",
                v
            );
        };

        v = mqo_cdr( src );
        if( mqo_is_pair( v ) ){
            src = mqo_pair_fv( v );
        }else{
            mqo_errf( 
                mqo_es_args,
                "sx", "map-car requires that its argument be a proper list",
                v 
            );
        }
    }
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( map_car );

MQO_BEGIN_PRIM( "map-cdr", map_cdr )
    REQ_PAIR_ARG( src );
    NO_MORE_ARGS( );
    mqo_tc tc = mqo_make_tc();
    while( src ){
        mqo_value v = mqo_car( src );
        if( mqo_is_pair( v ) ){
            mqo_tc_append( tc, mqo_cdr( mqo_pair_fv( v ) ) );
        }else{
            mqo_errf( 
                mqo_es_args,
                "sx", "map-cdr requires that all members of the list be pairs",
                v
            );
        };

        v = mqo_cdr( src );
        if( mqo_is_pair( v ) ){
            src = mqo_pair_fv( v );
        }else{
            mqo_errf( 
                mqo_es_args,
                "sx", "map-car requires that its argument be a proper list",
                v
            );
        }
    }
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( map_cdr );

MQO_BEGIN_PRIM( "thaw", thaw )
    REQ_STRING_ARG( src );
    NO_MORE_ARGS( );
    mqo_pair p = mqo_thaw_memory( mqo_sf_string( src ), 
                                  mqo_string_length( src ) );

    if( mqo_boolean_fv( mqo_car( p ) ) ){
        MQO_RESULT( mqo_cdr( p ) );    
    }else{
        mqo_errf( mqo_es_vm, "x", mqo_cdr( p ) );
        MQO_NO_RESULT( );
    }
MQO_END_PRIM( thaw );

MQO_BEGIN_PRIM( "string-append", string_append )
    mqo_integer ln = 0;
    if( ct == 1 ){
        MQO_RESULT( mqo_vector_get( MQO_SV, MQO_SI - 2  ) );
    };
    for( ai = ct;  ai; ai-- ){
        mqo_value v = mqo_vector_get( MQO_SV, MQO_SI - ai - 1 );
        if( mqo_is_string( v ) ){
            ln += mqo_string_length( mqo_string_fv( v ) );
        }else if( mqo_is_integer( v ) ){
            ln += 1;
        }else{
            mqo_errf( mqo_es_vm, "sx", "expected a string, got:", v );
            MQO_NO_RESULT( );
        };
    }
    
    mqo_string ds = mqo_make_string( ln );
    
    char* d = ds->data;

    for( ai = ct; ai; ai-- ){
        mqo_value v = mqo_vector_get( MQO_SV, MQO_SI - ai - 1 );
        if( mqo_is_string( v ) ){
            mqo_string ss = mqo_string_fv( v );
            mqo_integer sl = mqo_string_length( ss );
            memcpy( d, ss->data, sl );
            d += sl;
        }else{
            *d = (unsigned char)(mqo_integer_fv( v ) );
            d += 1;
        }
    };
    
    *d = 0;

    MQO_RESULT( mqo_vf_string( ds ) );
MQO_END_PRIM( string_append );

MQO_BEGIN_PRIM( "assq", assq )
    REQ_VALUE_ARG( key );
    REQ_PAIR_ARG( list );
    NO_MORE_ARGS( );
    
    mqo_value v;

    while( list ){
        v = mqo_car( list );
        if( mqo_is_pair( v ) ){
        //TODO: Should this be an error?
            if( mqo_eq( mqo_car( mqo_pair_fv( v ) ), key ) ){
                MQO_RESULT( v );
            }
        }
        v = mqo_cdr( list );
        if( ! mqo_is_pair( v ) )break;
        //TODO: Should this be an error?
        list = mqo_pair_fv( v );
    }

    MQO_RESULT( mqo_vf_false() );
MQO_END_PRIM( assq );

MQO_BEGIN_PRIM( "getcwd", getcwd )
    static char buf[ MAXPATHLEN ];
    if( getcwd( buf, MAXPATHLEN ) ){
        MQO_RESULT( mqo_vf_string( mqo_string_fs( buf ) ) );
    }else{
        mqo_errf( mqo_es_vm, "s", strerror( errno ) );
        MQO_NO_RESULT( );
    };
MQO_END_PRIM( getcwd )

MQO_BEGIN_PRIM( "argv", argv )
    OPT_INTEGER_ARG( ix );
    NO_MORE_ARGS( );
    if( has_ix ){
        if( ix < mqo_argc ){
            MQO_RESULT( mqo_car( mqo_list_ref( mqo_argv, ix ) ) );
        }else{
            MQO_RESULT( mqo_vf_false( ) );
        }
    }else{
        MQO_RESULT( mqo_vf_pair( mqo_argv ) );
    };
MQO_END_PRIM( argv )

MQO_BEGIN_PRIM( "argc", argc )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_integer( mqo_argc ) );
MQO_END_PRIM( argc )

MQO_BEGIN_PRIM( "make-type", make_type )
    REQ_SYMBOL_ARG( name );
    REQ_TYPE_ARG( super );
    REST_ARGS( info );
    MQO_RESULT( 
        mqo_vf_type( 
            mqo_make_type( 
                name, 
                super,
                NULL,
                info
            )
        )
    );
MQO_END_PRIM( make_type );

MQO_BEGIN_PRIM( "type-info", type_info )
    REQ_TYPE_ARG( type );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_pair( type->info ) );
MQO_END_PRIM( type_info );

MQO_BEGIN_PRIM( "tag", tag )
    REQ_TYPE_ARG( type );
    REQ_VALUE_ARG( repr );
    NO_MORE_ARGS( );

    mqo_type direct = mqo_type_direct( type );

    if( direct != mqo_direct_type( repr ) ){
        mqo_errf( 
            mqo_es_vm,
            "sxsx", 
            "tag expected",
            mqo_vf_type( type ),
            "to be derived from",
            mqo_vf_type( direct )
        );
    }else{
        MQO_RESULT( mqo_make_value( type, repr.data ) );
    };
MQO_END_PRIM( tag );

MQO_BEGIN_PRIM( "type", xtype )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_type( mqo_value_type( value ) ) );
MQO_END_PRIM( xtype );

MQO_BEGIN_PRIM( "repr", repr )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_make_value( mqo_direct_type( value ), value.data ) );
MQO_END_PRIM( repr );

MQO_BEGIN_PRIM( "isa?", isaq )
    REQ_VALUE_ARG( value );
    REQ_TYPE_ARG( type );
    NO_MORE_ARGS( );
   
    MQO_RESULT( mqo_vf_boolean( mqo_isa( value, type ) ) );
MQO_END_PRIM( isaq );

MQO_BEGIN_PRIM( "make-multimethod", make_multimethod )
    REQ_VALUE_ARG( sig );
    REQ_VALUE_ARG( pass );
    REQ_VALUE_ARG( fail );
    NO_MORE_ARGS( );

    if((! mqo_is_true( sig ))&&(! mqo_is_pair( sig ) )){
        mqo_errf( mqo_es_vm, "sx", "expected list or #t, not", sig );
    }

    if(! mqo_is_function( fail ) ){
        mqo_errf( mqo_es_vm, "sx", "expected function for fail, not", fail );
    }

    if(! mqo_is_function( pass ) ){
        mqo_errf( mqo_es_vm, "sx", "expected function for pass, not", pass );
    }

    MQO_RESULT( 
        mqo_vf_multimethod( mqo_make_multimethod( sig, pass, fail ) ) 
    );
MQO_END_PRIM( make_multimethod )

MQO_BEGIN_PRIM( "refuse-method", refuse_method )
    REST_ARGS( rest );
    NO_MORE_ARGS( );
    mqo_err( 
        mqo_es_vm,
        mqo_cons( mqo_vf_string( mqo_string_fs( "method not found" ) ), 
                  mqo_vf_pair( rest ) )
    );
MQO_END_PRIM( refuse_method )

int mqo_gc_stopper( ){ return 0; }
MQO_BEGIN_PRIM( "gc-now", gc_now )
    NO_MORE_ARGS( );
    GC_try_to_collect( mqo_gc_stopper );
    MQO_NO_RESULT( );
MQO_END_PRIM( gc_now )

MQO_BEGIN_PRIM( "get-global", get_global )
    REQ_SYMBOL_ARG( symbol );
    OPT_VALUE_ARG( def );
    NO_MORE_ARGS( );
    if(! mqo_is_void( symbol->value ) ){
        MQO_RESULT( symbol->value );
    }else if( has_def ){
        MQO_RESULT( def );
    }else{
        MQO_RESULT( mqo_vf_false() );
    }
MQO_END_PRIM( get_global )

MQO_BEGIN_PRIM( "cons*", consx )
    REST_ARGS( list )
    mqo_pair pair, next, last = NULL;
    for( pair = list; pair != NULL; pair = next ){
        next = mqo_req_pair( mqo_cdr( pair ), "pair" );
        if( next == NULL ){
            if( last != NULL ){ 
                mqo_set_cdr( last, mqo_car( pair ) );
            }
            break;
        }
        last = pair;
    }
    MQO_RESULT( mqo_vf_pair( list ) );
MQO_END_PRIM( consx )

MQO_BEGIN_PRIM( "enable-trace", enable_trace )
    NO_MORE_ARGS( );
    if( mqo_trace_vm < 1000 )mqo_trace_vm += 1;
    MQO_NO_RESULT();
MQO_END_PRIM( enable_trace )

MQO_BEGIN_PRIM( "disable-trace", disable_trace )
    NO_MORE_ARGS( );
    if( mqo_trace_vm )mqo_trace_vm -= 1;
    MQO_NO_RESULT();
MQO_END_PRIM( disable_trace )

MQO_BEGIN_PRIM( "make-tc", make_tc )
    OPT_PAIR_ARG( seed );
    NO_MORE_ARGS( );

    mqo_tc tc = mqo_make_tc( );

    if( has_seed && seed ){
        mqo_set_car( tc, mqo_vf_pair( seed ) );
        mqo_set_cdr( tc, mqo_vf_pair( mqo_last_pair( seed ) ) );
    };

    MQO_RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( make_tc )

MQO_BEGIN_PRIM( "tc-clear!", tc_clear )
    REQ_TC_ARG( tc );
    NO_MORE_ARGS( );
    mqo_set_car( tc, mqo_vf_empty() );
    mqo_set_cdr( tc, mqo_vf_empty() );
    MQO_RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_clear )

MQO_BEGIN_PRIM( "tc-splice!", tc_splice )
    REQ_TC_ARG( tc );
    REQ_PAIR_ARG( list );
    NO_MORE_ARGS( );

    if( mqo_is_empty( mqo_car( tc ) ) ){
        mqo_set_car( tc, v_list );
    }else{
        mqo_set_cdr( mqo_pair_fv( mqo_cdr( tc ) ), v_list );
    };

    mqo_set_cdr( tc, mqo_vf_pair( mqo_last_pair( list ) ) );
    MQO_RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_splice )

MQO_BEGIN_PRIM( "tc?", tcq )
    REQ_VALUE_ARG( value )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_tc( value ) ) );
MQO_END_PRIM( tcq )

MQO_BEGIN_PRIM( "program?", programq )
    REQ_VALUE_ARG( value )
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_program( value ) ) );
MQO_END_PRIM( programq )

MQO_BEGIN_PRIM( "tc-next!", tc_next )
    REQ_TC_ARG( tc );
    NO_MORE_ARGS( );
    if( mqo_is_empty( mqo_car( tc ) ) ){
        mqo_errf( mqo_es_vm, "s", "tconc out of items" );
    }
    mqo_pair next = mqo_pair_fv( mqo_car( tc ) );
    mqo_pair lead = mqo_pair_fv( mqo_cdr( next ) );
    if( lead ){
        mqo_set_car( tc, mqo_vf_pair( lead ) );
    }else{
        mqo_set_car( tc, mqo_vf_empty() );
        mqo_set_cdr( tc, mqo_vf_empty() );
    }
    MQO_RESULT( mqo_car( next ) );
MQO_END_PRIM( tc_next );

MQO_BEGIN_PRIM( "tc-empty?", tc_emptyq )
    REQ_TC_ARG( tc );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_empty( mqo_car( tc ) ) ) );
MQO_END_PRIM( tc_emptyq );

MQO_BEGIN_PRIM( "tc-append!", tc_append )
    REQ_TC_ARG( tc );
    REQ_VALUE_ARG( item );
    NO_MORE_ARGS( );

    item = mqo_vf_pair( mqo_cons( item, mqo_vf_empty() ) );

    if( mqo_is_empty( mqo_car( tc ) ) ){
        mqo_set_car( tc, item );
    }else{
        mqo_set_cdr( mqo_pair_fv( mqo_cdr( tc ) ), item );
    };

    mqo_set_cdr( tc, item );
    MQO_RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_append )

MQO_BEGIN_PRIM( "tc-prepend!", tc_prepend )
    REQ_TC_ARG( tc );
    REQ_VALUE_ARG( item );
    NO_MORE_ARGS( );
    item = mqo_vf_pair( mqo_cons( item, mqo_car( tc ) ) );

    if( mqo_is_empty( mqo_car( tc ) ) ){
        mqo_set_cdr( tc, item );
    };
    mqo_set_car( tc, item );

    MQO_RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_prepend )

MQO_BEGIN_PRIM( "tc->list", tc_to_list )
    REQ_TC_ARG( tc );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( tc_to_list )

MQO_BEGIN_PRIM( "string->exprs", string_to_exprs )
    REQ_STRING_ARG( src );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_pair( mqo_read_exprs( mqo_sf_string( src ) ) ) );
MQO_END_PRIM( string_to_exprs )

MQO_BEGIN_PRIM( "dump-lexicon", dump_lexicon )
    NO_MORE_ARGS( );
    mqo_show_tree( mqo_lexicon, 0 );
    MQO_NO_RESULT( );
MQO_END_PRIM( dump_lexicon )

MQO_BEGIN_PRIM( "dump-set", dump_set )
    REQ_SET_ARG( set );
    NO_MORE_ARGS( );
    mqo_dump_tree( set );
    MQO_NO_RESULT( );
MQO_END_PRIM( dump_set )

MQO_BEGIN_PRIM( "dump-dict", dump_dict )
    REQ_DICT_ARG( dict );
    NO_MORE_ARGS( );
    mqo_dump_tree( dict );
    MQO_NO_RESULT( );
MQO_END_PRIM( dump_dict )

MQO_BEGIN_PRIM( "dump-program", dump_program )
    REQ_PROGRAM_ARG( program );
    NO_MORE_ARGS( );
    mqo_dump_program( program );
    MQO_NO_RESULT( );
MQO_END_PRIM( dump_program )

MQO_BEGIN_PRIM( "globals", globals )
    NO_MORE_ARGS( );
    mqo_set globals = mqo_make_tree( mqo_set_key );
    MQO_ITER_TREE( mqo_lexicon, node ){
        mqo_symbol key = mqo_symbol_fv( node->data );
        if( ! mqo_is_void( key->value ) ){
            mqo_tree_insert( globals, node->data );
        }
    }
    MQO_RESULT( mqo_vf_set( globals ) );
MQO_END_PRIM( globals );

MQO_BEGIN_PRIM( "set", set )
    mqo_set set = mqo_make_tree( mqo_set_key );

    for( ai = ct;  ai; ai-- ){
        mqo_value item = mqo_vector_get( MQO_SV, MQO_SI - ai - 1 );
        mqo_tree_insert( set, item );
    }
    
    MQO_RESULT( mqo_vf_set( set ) );
MQO_END_PRIM( set )

MQO_BEGIN_PRIM( "set-add!", set_addd )
    REQ_SET_ARG( set );
    REQ_VALUE_ARG( item );
    NO_MORE_ARGS( );
    
    mqo_tree_insert( set, item );
    
    MQO_NO_RESULT( );
MQO_END_PRIM( set_addd )

MQO_BEGIN_PRIM( "set-remove!", set_removed )
    REQ_SET_ARG( set );
    REQ_VALUE_ARG( item );
    NO_MORE_ARGS( );
    
    mqo_tree_remove( set, item );
    
    MQO_NO_RESULT( );
MQO_END_PRIM( set_removed )

MQO_BEGIN_PRIM( "set-member?", set_memberq )
    REQ_SET_ARG( set );
    REQ_VALUE_ARG( item );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_tree_lookup( set, item ) ? mqo_vf_true() : mqo_vf_false() );
MQO_END_PRIM( set_memberq )

MQO_BEGIN_PRIM( "set->list", set_to_list )
    REQ_SET_ARG( set );
    NO_MORE_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    
    MQO_ITER_TREE( set, node ){
        mqo_tc_append( tc, node->data );
    }
    
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( set_to_list )

MQO_BEGIN_PRIM( "set?", setq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_boolean( mqo_is_set( value ) ) );
MQO_END_PRIM( setq )

MQO_BEGIN_PRIM( "dict", dict )
    mqo_dict dict = mqo_make_tree( mqo_dict_key );

    for( ai = ct;  ai; ai-- ){
        mqo_value item = mqo_vector_get( MQO_SV, MQO_SI - ai - 1 );
        mqo_tree_insert( dict, item );
    }
    
    MQO_RESULT( mqo_vf_dict( dict ) );
MQO_END_PRIM( dict )

MQO_BEGIN_PRIM( "dict?", dictq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_boolean( mqo_is_dict( value ) ) );
MQO_END_PRIM( dictq )

MQO_BEGIN_PRIM( "dict->list", dict_to_list )
    REQ_DICT_ARG( dict );
    NO_MORE_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    MQO_ITER_TREE( dict, node ){
        mqo_tc_append( tc, node->data );
    }
    
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( dict_to_list )

MQO_BEGIN_PRIM( "dict-keys", dict_keys )
    REQ_DICT_ARG( dict );
    NO_MORE_ARGS( );

    mqo_tc tc = mqo_make_tc( );

    MQO_ITER_TREE( dict, node ){
        mqo_tc_append( tc, mqo_car( mqo_pair_fv( node->data ) ) );
    }
    
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( dict_keys )

MQO_BEGIN_PRIM( "dict-values", dict_values )
    REQ_DICT_ARG( dict );
    NO_MORE_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    
    MQO_ITER_TREE( dict, node ){
        mqo_tc_append( tc, mqo_cdr( mqo_pair_fv( node->data ) ) );
    }
    
    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( dict_values )

MQO_BEGIN_PRIM( "dict-set?", dict_setq )
    REQ_DICT_ARG( dict );
    REQ_VALUE_ARG( key );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_tree_lookup( dict, key ) ? mqo_vf_true() : mqo_vf_false() );    
MQO_END_PRIM( dict_setq )

MQO_BEGIN_PRIM( "dict-set!", dict_setd )
    REQ_DICT_ARG( dict );
    REQ_VALUE_ARG( key );
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    
    mqo_tree_insert( dict, mqo_vf_pair( mqo_cons( key, value ) ) );

    MQO_NO_RESULT();
MQO_END_PRIM( dict_setd )

MQO_BEGIN_PRIM( "dict-ref", dict_ref )
    REQ_DICT_ARG( dict );
    REQ_VALUE_ARG( key );
    OPT_VALUE_ARG( alternate );
    NO_MORE_ARGS( );
   
    mqo_node node = mqo_tree_lookup( dict, key );
    
    if( node ){
        MQO_RESULT( mqo_cdr( mqo_pair_fv( node->data ) ) );
    }else if( has_alternate ){
        MQO_RESULT( alternate );
    }else{
        MQO_RESULT( mqo_vf_false() );
    }
MQO_END_PRIM( dict_ref )

MQO_BEGIN_PRIM( "dict-remove!", dict_removed )
    REQ_DICT_ARG( dict );
    REQ_VALUE_ARG( item );
    NO_MORE_ARGS( );
    
    mqo_tree_remove( dict, item );
    
    MQO_NO_RESULT( );
MQO_END_PRIM( dict_removed )

char* mqo_memmem( const char* sp, mqo_integer sl, const char* ip, mqo_integer il ){
    // Like strstr, but \0-ignorant.
    if( sl < il )return NULL;

    sl -= il;

    for( mqo_integer i = 0; i < sl; i ++ ){
        if( ! memcmp( sp, ip, il ) ) return (char*)sp;
        sp++;
    }

    return NULL;
}

MQO_BEGIN_PRIM( "string-find", string_find )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_MORE_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    const char* ip = mqo_memmem( sp, 
                             mqo_string_length( string ), 
                             mqo_sf_string( item ), 
                             mqo_string_length( item ) );
    
    if( ip ){
        MQO_RESULT( mqo_vf_integer( ip - sp ) );
    }else{
        MQO_RESULT( mqo_vf_false( ) );
    }
MQO_END_PRIM( string_find )

MQO_BEGIN_PRIM( "string-begins-with", string_begins_with )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    
    mqo_integer sl = mqo_string_length( string );
    mqo_integer il = mqo_string_length( item );

    if( sl < il ){
        MQO_RESULT( mqo_vf_false( ) );
    }else{
        const char* sp = mqo_sf_string( string );
        const char* ip = mqo_sf_string( item );

        MQO_RESULT( mqo_vf_boolean( ! memcmp( sp, ip, il ) ) );
    }
MQO_END_PRIM( string_begins_with )

MQO_BEGIN_PRIM( "string-ends-with", string_ends_with )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    
    mqo_integer sl = mqo_string_length( string );
    mqo_integer il = mqo_string_length( item );

    if( sl < il ){
        MQO_RESULT( mqo_vf_false( ) );
    }else{
        const char* sp = mqo_sf_string( string ) + sl - il;
        const char* ip = mqo_sf_string( item );

        MQO_RESULT( mqo_vf_boolean( ! memcmp( sp, ip, il ) ) );
    }
MQO_END_PRIM( string_ends_with )

MQO_BEGIN_PRIM( "split-lines", split_lines )
    REQ_STRING_ARG( string );
    NO_MORE_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    const char* bp = sp;
    mqo_pair tc = mqo_make_tc( tc );
    char ch;

    void add_item( ){
        mqo_tc_append( tc, mqo_vf_string( mqo_string_fm( bp, sp - bp ) ) );
    }

    while( ch = *sp ){
        switch( ch ){
        case '\r':
            add_item( );
            if( sp[1] == '\n' ) sp++;
            bp = sp + 1;
            break;
        case '\n':
            add_item( );
            bp = sp + 1;
            break;
        };
        sp ++;
    };

    add_item( );

    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( split_lines )

MQO_BEGIN_PRIM( "string-split", string_split )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_MORE_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    mqo_integer sl = mqo_string_length( string );
    const char* ip = mqo_sf_string( item );
    mqo_integer il = mqo_string_length( item );
    const char* pp = mqo_memmem( sp, sl, ip, il );
    
    if( pp ){
        mqo_integer pl = pp - sp;
        item = mqo_string_fm( sp, pl );
        string = mqo_string_fm( pp + il, sl - il - pl );
    }else{
        item = string;
        string = mqo_make_string( 0 );
    }

    MQO_RESULT( 
        mqo_vf_pair( mqo_cons( mqo_vf_string( item ),
                               mqo_vf_pair( 
                                   mqo_cons( mqo_vf_string( string ),
                                             mqo_vf_empty( ) ) ) ) ) );
MQO_END_PRIM( string_split )

MQO_BEGIN_PRIM( "string-split*", string_splitm )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_MORE_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    mqo_integer sl = mqo_string_length( string );

    const char* ip = mqo_sf_string( item );
    mqo_integer il = mqo_string_length( item );
    
    mqo_tc tc = mqo_make_tc( );
    const char* pp;
  
    while( pp = mqo_memmem( sp, sl, ip, il ) ){
        mqo_integer pl = pp - sp;
        item = mqo_string_fm( sp, pl );
        mqo_tc_append( tc, mqo_vf_string( item ) );    
        sl = sl - pl - il;
        sp = sp + pl + il;
    }
    
    mqo_tc_append( tc, mqo_vf_string( mqo_string_fm( sp, sl ) ) );

    MQO_RESULT( mqo_car( tc ) );
MQO_END_PRIM( string_splitm )

MQO_BEGIN_PRIM( "string-join", string_join )
    // Most languages use join( list, sep ), but in Lisp, it's always nice
    // to ensure that the list argument is last, to permit the use and
    // abuse of Apply, e.g.
    //
    // (apply string-join ", " items)
    
    REQ_STRING_ARG( sep );
    mqo_integer seplen = mqo_string_length( sep );
    mqo_integer ln = 0;

    for( ai = 1; ai < ct; ai++ ){
        mqo_value v = mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 );
        if( mqo_is_string( v ) ){
            ln += mqo_string_length( mqo_string_fv( v ) );
            if( (ai+1) < ct ){
                ln += seplen;
            }
        }else{
            mqo_errf( mqo_es_vm, "sx", "expected a string, got:", v );
            MQO_NO_RESULT( );
        };
    }
    
    mqo_string ds = mqo_make_string( ln );
    
    char* d = ds->data;

    for( ai = 1; ai < ct; ai++ ){
        mqo_string ss = mqo_string_fv( mqo_vector_get( MQO_SV, 
                                                       MQO_SI + ai - ct - 1 ) );
        mqo_integer sl = mqo_string_length( ss );
        memcpy( d, ss->data, sl );
        d += sl;
        if( (ai+1) < ct ){
            memcpy( d, sep->data, seplen );
            d += seplen;
        }
    };
    
    *d = 0;
    
    MQO_RESULT( mqo_vf_string( ds ) );
MQO_END_PRIM( string_join )

MQO_BEGIN_PRIM( "spawn", spawn )
    REQ_VALUE_ARG( fn );
    NO_MORE_ARGS( );
    
    //TODO: req function, here.
    mqo_process ps = mqo_spawn( fn );

    MQO_RESULT( mqo_vf_process( ps ) );
MQO_END_PRIM( spawn )

MQO_BEGIN_PRIM( "pause", pause )
    NO_MORE_ARGS( );

    //Since MQO_PAUSE is going to leap right out of the primitive,
    //we have to do the stack busywork ourselves, otherwise.. Well..
    //I'm not quite sure what'll happen, but it'll be bad!
    
    mqo_pop_ds();
    mqo_push_ds( mqo_vf_false() ); 
    mqo_return();

    MQO_PAUSE();
MQO_END_PRIM( pause )

MQO_BEGIN_PRIM( "suspend", suspend )
    NO_MORE_ARGS( );
    mqo_pop_ds();
    mqo_return();
    MQO_SUSPEND();
MQO_END_PRIM( suspend )

MQO_BEGIN_PRIM( "resume", resume )
    REQ_PROCESS_ARG( process );
    OPT_VALUE_ARG( value );
    NO_MORE_ARGS( );
    
    if( process->status != mqo_ps_suspended ){
        mqo_errf( mqo_es_vm, "sx", "only suspended processes may be resumed" ,
                                    v_process );
    }else{
        mqo_resume( process, value );
    }
    
    MQO_NO_RESULT( );
MQO_END_PRIM( resume )

MQO_BEGIN_PRIM( "halt", halt )
    OPT_PROCESS_ARG( process );
    NO_MORE_ARGS( );
   
    if( ! has_process )process = MQO_PP;

    if( process == MQO_PP ){
        MQO_HALT( );
    }else{
        process->status = mqo_ps_halted;
        mqo_unsched_process( process );
    }
MQO_END_PRIM( halt )

MQO_BEGIN_PRIM( "process-status", process_status )
    REQ_PROCESS_ARG( process );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_symbol( process->status ) );
MQO_END_PRIM( process_status )

MQO_BEGIN_PRIM( "active-process", active_process )
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_process( MQO_PP ) );
MQO_END_PRIM( active_process )

MQO_BEGIN_PRIM( "process?", processq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );
    MQO_RESULT( mqo_vf_boolean( mqo_is_process( value )  ) );
MQO_END_PRIM( processq )

void mqo_bind_core_prims( ){
    // R5RS Standards
    MQO_BIND_PRIM( symbolq );
    MQO_BIND_PRIM( stringq );
    MQO_BIND_PRIM( integerq );
    MQO_BIND_PRIM( pairq );
    MQO_BIND_PRIM( listq );
    MQO_BIND_PRIM( nullq );
    MQO_BIND_PRIM( cons );
    MQO_BIND_PRIM( car );
    MQO_BIND_PRIM( cdr );
    MQO_BIND_PRIM( cadr );
    MQO_BIND_PRIM( caddr );
    MQO_BIND_PRIM( set_car );
    MQO_BIND_PRIM( set_cdr );
    MQO_BIND_PRIM( length );
    MQO_BIND_PRIM( list );
    MQO_BIND_PRIM( make_vector );
    MQO_BIND_PRIM( vector );
    MQO_BIND_PRIM( vector_set );
    MQO_BIND_PRIM( vector_ref );
    MQO_BIND_PRIM( vector_length );
    MQO_BIND_PRIM( vectorq );
    MQO_BIND_PRIM( eq );
    MQO_BIND_PRIM( apply );
    MQO_BIND_PRIM( memq );
    MQO_BIND_PRIM( assq );
    MQO_BIND_PRIM( string_append );
    MQO_BIND_PRIM( string_length );
    MQO_BIND_PRIM( string_ref );
    MQO_BIND_PRIM( append );
    MQO_BIND_PRIM( appendd );
    MQO_BIND_PRIM( list_index );
    MQO_BIND_PRIM( list_ref );
    MQO_BIND_PRIM( m_lt );    
    MQO_BIND_PRIM( m_gt );    
    MQO_BIND_PRIM( m_lte );    
    MQO_BIND_PRIM( m_gte );    
    MQO_BIND_PRIM( m_eq );    
    MQO_BIND_PRIM( m_ne );    
    MQO_BIND_PRIM( m_add );    
    MQO_BIND_PRIM( m_sub );    
    MQO_BIND_PRIM( m_mul );    
    MQO_BIND_PRIM( m_div );    
    MQO_BIND_PRIM( m_abs );    
    MQO_BIND_PRIM( quotient );    
    MQO_BIND_PRIM( remainder );    
    MQO_BIND_PRIM( string_eqq );    
    MQO_BIND_PRIM( exit );    
    MQO_BIND_PRIM( number_to_string );    
    MQO_BIND_PRIM( string_to_symbol );    
    MQO_BIND_PRIM( symbol_to_string );    
    MQO_BIND_PRIM( last_item );
    MQO_BIND_PRIM( last_pair );
    MQO_BIND_PRIM( not );
    MQO_BIND_PRIM( equalq );    
    MQO_BIND_PRIM( eqvq );    
    MQO_BIND_PRIM( reverse );    
    MQO_BIND_PRIM( reversed );    

    // Extensions to R5RS
    MQO_BIND_PRIM( show );
    MQO_BIND_PRIM( errorq );
    MQO_BIND_PRIM( error );
    MQO_BIND_PRIM( error_key );
    MQO_BIND_PRIM( error_info );
    MQO_BIND_PRIM( error_state );
    MQO_BIND_PRIM( il_traceback );

    MQO_BIND_PRIM( vmstate_ip );
    MQO_BIND_PRIM( vmstate_cp );
    MQO_BIND_PRIM( vmstate_sv );
    MQO_BIND_PRIM( vmstate_rv );
    MQO_BIND_PRIM( vmstate_ep );
    MQO_BIND_PRIM( vmstate_gp );
    
    MQO_BIND_PRIM( map_car );
    MQO_BIND_PRIM( map_cdr );

    MQO_BIND_PRIM( thaw );
    MQO_BIND_PRIM( getcwd );
    MQO_BIND_PRIM( argv );
    MQO_BIND_PRIM( argc );

    MQO_BIND_PRIM( make_type );
    MQO_BIND_PRIM( tag );
    MQO_BIND_PRIM( xtype );
    MQO_BIND_PRIM( repr );
    MQO_BIND_PRIM( isaq );
    MQO_BIND_PRIM( type_info );

    MQO_BIND_PRIM( make_multimethod );
    MQO_BIND_PRIM( refuse_method );

    MQO_BIND_PRIM( gc_now );
    MQO_BIND_PRIM( get_global );
    
    MQO_BIND_PRIM( consx );
    
    MQO_BIND_PRIM( enable_trace );
    MQO_BIND_PRIM( disable_trace );

    MQO_BIND_PRIM( make_tc );
    MQO_BIND_PRIM( tc_splice );
    MQO_BIND_PRIM( tc_append );
    MQO_BIND_PRIM( tc_prepend );
    MQO_BIND_PRIM( tc_to_list );
    MQO_BIND_PRIM( tc_next );
    MQO_BIND_PRIM( tc_emptyq );
    MQO_BIND_PRIM( tcq );
    MQO_BIND_PRIM( tc_clear );

    MQO_BIND_PRIM( programq );

    MQO_BIND_PRIM( string_to_exprs );

    MQO_BIND_PRIM( dump_lexicon );
    MQO_BIND_PRIM( dump_set );
    MQO_BIND_PRIM( dump_dict );
    MQO_BIND_PRIM( dump_program );
    
    MQO_BIND_PRIM( set );
    MQO_BIND_PRIM( setq );
    MQO_BIND_PRIM( set_addd );
    MQO_BIND_PRIM( set_removed );
    MQO_BIND_PRIM( set_memberq );
    MQO_BIND_PRIM( set_to_list );
    
    MQO_BIND_PRIM( dict );
    MQO_BIND_PRIM( dictq );
    MQO_BIND_PRIM( dict_setd );
    MQO_BIND_PRIM( dict_ref );
    MQO_BIND_PRIM( dict_removed );
    MQO_BIND_PRIM( dict_setq );
    MQO_BIND_PRIM( dict_to_list );
    MQO_BIND_PRIM( dict_keys );
    MQO_BIND_PRIM( dict_values );

    MQO_BIND_PRIM( string_find );
    MQO_BIND_PRIM( string_split );
    MQO_BIND_PRIM( string_splitm );
    MQO_BIND_PRIM( string_join );
    MQO_BIND_PRIM( string_begins_with );
    MQO_BIND_PRIM( string_ends_with );

    MQO_BIND_PRIM( split_lines );
    
    MQO_BIND_PRIM( spawn );
    MQO_BIND_PRIM( pause );
    MQO_BIND_PRIM( halt );
    MQO_BIND_PRIM( suspend );
    MQO_BIND_PRIM( resume );
    MQO_BIND_PRIM( process_status );
    MQO_BIND_PRIM( active_process );
    MQO_BIND_PRIM( processq );

    MQO_BIND_PRIM( globals );

    mqo_symbol_fs( "atom" )->value = mqo_make_atom( );
}
