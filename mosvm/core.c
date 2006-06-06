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
#include <unistd.h>
#include <ctype.h>
#include <sys/param.h>
#include <errno.h>
#ifndef _WIN32
#include <arpa/inet.h>
#endif

MQO_BEGIN_PRIM( "xml-escape", xml_escape )
    REQ_STRING_ARG( data );
    NO_REST_ARGS( );
    
    const char* src = mqo_sf_string( data );
    int ix, srclen = mqo_string_length( data );
    mqo_string result = mqo_make_string( srclen );
    
    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        switch( ch ){
        case '\'':
            mqo_format_cs( result, "&apos;" );
            break;
        case '"':
            mqo_format_cs( result, "&quot;" );
            break;
        case '&':
            mqo_format_cs( result, "&amp;" );
            break;
        case '<':
            mqo_format_cs( result, "&lt;" );
            break;
        case '>':
            mqo_format_cs( result, "&gt;" );
            break;
        default:
            mqo_format_char( result, ch );
        };
    }
    
    RESULT( mqo_vf_string( result ) );
MQO_END_PRIM( xml_escape )

MQO_BEGIN_PRIM( "percent-encode", percent_encode )
    REQ_STRING_ARG( data );
    REQ_STRING_ARG( mask );
    NO_REST_ARGS( );
    
    char* maskstr = mqo_sf_string( mask );

    const char* src = mqo_sf_string( data );
    int ix, srclen = mqo_string_length( data );
    mqo_string result = mqo_make_string( srclen );
    
    for( ix = 0; ix < srclen; ix ++ ){
        char ch = src[ix];
        if( ch == '%' || strchr( maskstr, ch ) ){
            mqo_format_char( result, '%' );
            mqo_format_hex( result, ch );
        }else{
            mqo_format_char( result, ch );
        }
    }
    
    RESULT( mqo_vf_string( result ) );
MQO_END_PRIM( percent_encode )

MQO_BEGIN_PRIM( "percent-decode", percent_decode )
    REQ_STRING_ARG( data );
    NO_REST_ARGS( );

    char* src = mqo_sf_string( data );
    int srclen = mqo_string_length( data );
    mqo_string result = mqo_make_string( srclen );
    char ch;

    while( ch = *src ){
        src ++;
        if( ch == '%' ){
            mqo_boolean ok = 1;
            ch = (unsigned char)mqo_parse_hex( &src, &ok );
            if( ! ok )mqo_errf( mqo_es_vm, "sxs", "invalid escape", data, src );
        }
        mqo_format_char( result, ch );
    }
    
    RESULT( mqo_vf_string( result ) );
MQO_END_PRIM( percent_decode )

void mqo_untree_cb( mqo_value value, mqo_tc tc ){
    mqo_tc_append( tc, value );
}

MQO_BEGIN_PRIM( "string->integer", string_to_integer )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( )
    
    char* hd = mqo_sf_string( string );
    char* pt = hd;
    int ok = 0;

    mqo_integer i = mqo_parse_int( &pt, &ok );

    if( ! ok ){
        mqo_errf( mqo_es_vm, "s", "could not parse integer" );
    }else if( ( pt - hd ) != mqo_string_length( string ) ){
        mqo_errf( mqo_es_vm, "ss", "garbage trails integer", hd );
    }
    RESULT( mqo_vf_integer( i ) );
MQO_END_PRIM( string_to_integer )

MQO_BEGIN_PRIM( "cadr", cadr )
    REQ_PAIR_ARG( pair )
    NO_REST_ARGS( )
    
    pair = mqo_req_pair( mqo_cdr( pair ) );

    RESULT( mqo_car( pair ) );
MQO_END_PRIM( cadr );

MQO_BEGIN_PRIM( "reverse", reverse )
    REQ_LIST_ARG( pair );
    NO_REST_ARGS( )
    
    mqo_pair ep = NULL;
    while( pair ){
        ep = mqo_cons( mqo_car( pair ), mqo_vf_list( ep ) );
        pair = mqo_req_list( mqo_cdr( pair ) );
    }
    RESULT( mqo_vf_list( ep ) );
MQO_END_PRIM( reverse );

MQO_BEGIN_PRIM( "reverse!", reversed )
    REQ_LIST_ARG( pair );
    NO_REST_ARGS( )
    
    mqo_pair ep = NULL;
    mqo_pair next;
    while( pair ){
        next = mqo_req_list( mqo_cdr( pair ) );
        mqo_set_cdr( pair, mqo_vf_pair( ep ) );
        ep = pair;
        pair = next;
    }
    RESULT( mqo_vf_list( ep ) );
MQO_END_PRIM( reversed );

MQO_BEGIN_PRIM( "caddr", caddr )
    REQ_PAIR_ARG( pair )
    NO_REST_ARGS( )
    
    pair = mqo_req_pair( mqo_cdr( pair ) );
    pair = mqo_req_pair( mqo_cdr( pair ) );

    RESULT( mqo_car( pair ) );
MQO_END_PRIM( caddr );

MQO_BEGIN_PRIM( "equal?", equalq )
    REQ_ANY_ARG( v0 );
    for(;;){
        OPT_ANY_ARG( vN );
        if( ! has_vN )break;
        if( mqo_cmp_eq( v0, vN ) ){
            RESULT( mqo_vf_false( ) );
        }
    }
    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( equalq );

MQO_BEGIN_PRIM( "not", not )
    REQ_ANY_ARG( value )
    NO_REST_ARGS( );
    
    RESULT( mqo_vf_boolean( mqo_is_false( value ) ) );
MQO_END_PRIM( not )

MQO_BEGIN_PRIM( "last-pair", last_pair )
    REQ_LIST_ARG( list )
    NO_REST_ARGS( );
    RESULT( mqo_vf_pair( mqo_last_pair( list ) ) ); 
MQO_END_PRIM( last_pair )

MQO_BEGIN_PRIM( "last-item", last_item )
    REQ_LIST_ARG( list )
    NO_REST_ARGS( );
    RESULT( mqo_car( mqo_last_pair( list ) ) ); 
MQO_END_PRIM( last_item )

MQO_BEGIN_PRIM( "list-ref", list_ref )
    REQ_PAIR_ARG( list );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );

    while( list && index > 0 ){
        index --; list = mqo_req_list( mqo_cdr( list ));
    }
    if( list == NULL )mqo_errf( mqo_es_vm, "s", "index past end of list" );
    RESULT( mqo_car( list ) );
MQO_END_PRIM( list_ref )

MQO_BEGIN_PRIM( "abs", m_abs )
    REQ_INTEGER_ARG( integer );
    NO_REST_ARGS( );
    
    RESULT( mqo_vf_integer( integer < 0 ?  -integer : integer ) );
MQO_END_PRIM( m_abs )

MQO_BEGIN_PRIM( "+", m_add )
    REQ_INTEGER_ARG( v0 );
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        v0 += vN;
    };
    RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_add )

MQO_BEGIN_PRIM( "-", m_sub )
    REQ_INTEGER_ARG( v0 );
    int any = 0;
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        v0 -= vN;
        any = 1;
    };
    if( ! any ) v0 = -v0;
    RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_sub )

MQO_BEGIN_PRIM( "*", m_mul )
    REQ_INTEGER_ARG( v0 );
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        v0 *= vN;
    };
    RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_mul )

MQO_BEGIN_PRIM( "/", m_div )
    REQ_INTEGER_ARG( v0 );
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        v0 /= vN;
    };
    RESULT( mqo_vf_integer( v0 ) );
MQO_END_PRIM( m_div )

MQO_BEGIN_PRIM( "quotient", quotient )
    REQ_INTEGER_ARG( n1 );
    REQ_INTEGER_ARG( n2 );
    NO_REST_ARGS( );

    if(! n2 ){
        mqo_errf( mqo_es_vm, "s", "attempted divide by zero" );
    }
    RESULT( mqo_vf_integer( n1 / n2 ) );
MQO_END_PRIM( quotient )

MQO_BEGIN_PRIM( "remainder", remainder )
    REQ_INTEGER_ARG( n1 );
    REQ_INTEGER_ARG( n2 );
    NO_REST_ARGS( );

    if(! n2 ){
        mqo_errf( mqo_es_vm, "s", "attempted divide by zero" );
    }
    RESULT( mqo_vf_integer( n1 % n2 ) );
MQO_END_PRIM( remainder )

MQO_BEGIN_PRIM( "number->string", number_to_string )
    /* "Time they say is the great healer, but I believe in chemicals, baby."
     * -- Fatboy Slim, "Push and Shove" */

    /* There is precisely one way to output a number in base 10 in the standard
       C library. But I'll be damned if I'll use sprintf. */
    REQ_INTEGER_ARG( number );
    NO_REST_ARGS( );
    
    //TODO: format / print / redundant

    static char buf[256];
    buf[255] = 0;
    int i = 255;
    int neg = number < 0;
    if( neg ){ number = -number; };

    do{
        buf[ --i ] = '0' + number % 10;
    }while( number /= 10 );

    if( neg )buf[ -- i ] = '-';

    RESULT( mqo_vf_string( mqo_string_fm( buf + i, 255 - i ) ) );
MQO_END_PRIM( number_to_string );

MQO_BEGIN_PRIM( "string->symbol", string_to_symbol )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    RESULT( mqo_vf_symbol( mqo_symbol_fs( mqo_sf_string( string ) ) ) );
MQO_END_PRIM( string_to_symbol );

MQO_BEGIN_PRIM( "symbol->string", symbol_to_string )
    REQ_SYMBOL_ARG( symbol );
    NO_REST_ARGS( );
    RESULT( mqo_vf_string( symbol->string ) );
MQO_END_PRIM( symbol_to_string );

MQO_BEGIN_PRIM( "make-vector", make_vector )
    REQ_INTEGER_ARG( length );
    OPT_ANY_ARG( init );
    NO_REST_ARGS( );
    
    if( length < 0 )mqo_errf( mqo_es_vm, "si", "expected non-negative",
                                length );

    mqo_vector vect = mqo_make_vector( length );

    if( has_init ){
        while( length-- ){
            mqo_vector_put( vect, length, init );
        }
    }
    RESULT( mqo_vf_vector( vect ) );
MQO_END_PRIM( make_vector )

MQO_BEGIN_PRIM( "list-index", list_index )
    REQ_ANY_ARG( item );
    REQ_PAIR_ARG( list );
    NO_REST_ARGS( );
    mqo_integer ix = 0;

    while( list ){
        if( mqo_eq( mqo_car( list ), item ) ){
            RESULT( mqo_vf_integer( ix ) );
        }
        ix++;
        mqo_value v = mqo_cdr( list );
        if(!  mqo_is_pair( v ) ){
            NO_RESULT();
        };
        list = mqo_list_fv( v );
    }
    NO_RESULT();
MQO_END_PRIM( list_index );

MQO_BEGIN_PRIM( "memq", memq )
    REQ_ANY_ARG( item );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    while( list ){
        if( mqo_eq( item, mqo_car( list ) ) ){
            RESULT( mqo_vf_pair( list ) );
        }
        list = mqo_list_fv( mqo_cdr( list ) );
    }
    RESULT( mqo_vf_false() );
MQO_END_PRIM( memq );

MQO_BEGIN_PRIM( "member", member )
    REQ_ANY_ARG( item );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    while( list ){
        if( ! mqo_cmp_eq( item, mqo_car( list ) ) ){
            RESULT( mqo_vf_pair( list ) );
        }
        list = mqo_list_fv( mqo_cdr( list ) );
    }
    RESULT( mqo_vf_false() );
MQO_END_PRIM( member );

MQO_BEGIN_PRIM( "exit", exit )
    OPT_INTEGER_ARG( code );
    NO_REST_ARGS( );
    exit( has_code ? code : 0 );
MQO_END_PRIM( exit )

MQO_BEGIN_PRIM( "equal?", equal )
    REQ_ANY_ARG( v0 );
    for(;;){
        OPT_ANY_ARG( vN );
        if( ! has_vN )break;
        if( ! mqo_eqv( v0, vN ) ){
            RESULT( mqo_vf_false( ) );
        }
    }
    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( equal )

MQO_BEGIN_PRIM( "eq?", eq )
    REQ_ANY_ARG( v0 );
    for(;;){
        OPT_ANY_ARG( vN );
        if( ! has_vN )break;
        if( ! mqo_eq( v0, vN ) ){
            RESULT( mqo_vf_false( ) );
        }
    }
    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( eq )

MQO_BEGIN_PRIM( "list?", listq )
    REQ_ANY_ARG( v );
    NO_REST_ARGS( );
    BOOLEAN_RESULT( mqo_is_list( v ) );
MQO_END_PRIM( listq )

MQO_BEGIN_PRIM( "integer?", integerq )
    REQ_ANY_ARG( v );
    NO_REST_ARGS( );
    RESULT( mqo_vf_boolean( ( mqo_is_integer( v ) ) ) );
MQO_END_PRIM( integerq )

MQO_BEGIN_PRIM( "cons", cons )
    REQ_ANY_ARG( car );
    REQ_ANY_ARG( cdr );
    NO_REST_ARGS( );
    RESULT( mqo_vf_pair( mqo_cons( car, cdr ) ) );
MQO_END_PRIM( cons )

MQO_BEGIN_PRIM( "car", car )
    REQ_PAIR_ARG( p );
    NO_REST_ARGS( );
    RESULT( mqo_car( p ) );
MQO_END_PRIM( car )

MQO_BEGIN_PRIM( "cdr", cdr )
    REQ_PAIR_ARG( p );
    NO_REST_ARGS( );
    RESULT( mqo_cdr( p ) );
MQO_END_PRIM( cdr )

MQO_BEGIN_PRIM( "set-car!", set_car )
    REQ_PAIR_ARG( p );
    REQ_ANY_ARG( car );
    NO_REST_ARGS( );
    mqo_set_car( p, car );
    NO_RESULT( );
MQO_END_PRIM( set_car )

MQO_BEGIN_PRIM( "set-cdr!", set_cdr )
    REQ_PAIR_ARG( p );
    REQ_ANY_ARG( cdr );
    NO_REST_ARGS( );
    mqo_set_cdr( p, cdr );
    NO_RESULT( );
MQO_END_PRIM( set_cdr )

MQO_BEGIN_PRIM( "vector", vector )
    mqo_vector vt = mqo_make_vector( mqo_arg_ct );
    mqo_integer ix = 0;
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item ) break;
        mqo_vector_put( vt, ix, item );
        ix ++;
    }
    RESULT( mqo_vf_vector( vt ) );
MQO_END_PRIM( vector )

MQO_BEGIN_PRIM( "vector-ref", vector_ref )
    REQ_VECTOR_ARG( vector );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );
    if( index < mqo_vector_length( vector ) ){
        RESULT( mqo_vector_get( vector, index ) );
    }else{
        mqo_errf( 
            mqo_es_vm,
            "si", "index exceeds vector length", mqo_vector_length( vector ) 
        );
        NO_RESULT( );
    }
MQO_END_PRIM( vector_ref )

MQO_BEGIN_PRIM( "vector-set!", vector_set )
    REQ_VECTOR_ARG( vector );
    REQ_INTEGER_ARG( index );
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    if( index < mqo_vector_length( vector ) ){
        mqo_vector_put( vector, index, value );
    }else{
        mqo_errf( 
            mqo_es_vm,
            "si", "index exceeds vector length", 
            mqo_vector_length( vector ) 
        );
    };
    NO_RESULT( );
MQO_END_PRIM( vector_set )

MQO_BEGIN_PRIM( "vector-length", vector_length )
    REQ_VECTOR_ARG( vector );
    NO_REST_ARGS( );
    RESULT( mqo_vf_integer( mqo_vector_length( vector ) ) );
MQO_END_PRIM( vector_length )

MQO_BEGIN_PRIM( "string-length", string_length )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    RESULT( mqo_vf_integer( mqo_string_length( string ) ) );
MQO_END_PRIM( string_length )

MQO_BEGIN_PRIM( "substring", substring )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    REQ_INTEGER_ARG( length );
    NO_REST_ARGS( );

    const char* data = mqo_sf_string( string );
    mqo_integer datalen = mqo_string_length( string );
    
    if( index < 0 ) mqo_errf( mqo_es_vm, "s", "index must not be negative" );
    if( index > datalen ) mqo_errf( mqo_es_vm, "s", 
                                    "index must be not exceed the string"
                                    " length" );
    if( length < 0 ) mqo_errf( mqo_es_vm, "s", 
                               "length must not be negative" );
    if( length > datalen ) mqo_errf( mqo_es_vm, "s", 
                                    "length must be not exceed the string"
                                    " length" );
    if( (length + index) > datalen ){
        mqo_errf( mqo_es_vm, "s", 
                  "the sum of index and length must not exceed the"
                  " string length" 
        );
    }

    RESULT( mqo_vf_string( mqo_string_fm( data + index, length ) ) );
MQO_END_PRIM( substring )

MQO_BEGIN_PRIM( "string-head", string_head )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( length );
    NO_REST_ARGS( );

    const char* data = mqo_sf_string( string );
    mqo_integer datalen = mqo_string_length( string );
    
    if( length < 0 ) mqo_errf( mqo_es_vm, "s", 
                               "length must not be negative" );
    if( length > datalen ) length = datalen;
    RESULT( mqo_vf_string( mqo_string_fm( data, length ) ) );
MQO_END_PRIM( string_head )

MQO_BEGIN_PRIM( "string-tail", string_tail )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );

    const char* data = mqo_sf_string( string );
    mqo_integer datalen = mqo_string_length( string );
    mqo_integer length = datalen - index;

    if( index < 0 ) mqo_errf( mqo_es_vm, "s", 
                               "index must not be negative" );
    if( length > datalen ) length = datalen;
    RESULT( mqo_vf_string( mqo_string_fm( data + index, length ) ) );
MQO_END_PRIM( string_tail )

MQO_BEGIN_PRIM( "string-ref", string_ref )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( index );
    NO_REST_ARGS( );
    if( index >= mqo_string_length( string ) ){
        mqo_errf( mqo_es_vm, "si", "index exceeds string length", 
                               index );
    }
    RESULT( mqo_vf_integer( mqo_sf_string( string )[index] ) );
MQO_END_PRIM( string_ref )

MQO_BEGIN_PRIM( "=", m_eq )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 == vN ) ){ RESULT( mqo_vf_false( ) ); };
    };

    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( m_eq )

MQO_BEGIN_PRIM( "<", m_lt )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 < vN ) ){ RESULT( mqo_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( m_lt )

MQO_BEGIN_PRIM( ">", m_gt )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 > vN ) ){ RESULT( mqo_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( m_gt )

MQO_BEGIN_PRIM( "<=", m_lte )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 <= vN ) ){ RESULT( mqo_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( m_lte )

MQO_BEGIN_PRIM( ">=", m_gte )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 >= vN ) ){ RESULT( mqo_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( m_gte )

MQO_BEGIN_PRIM( "!=", m_ne )
    REQ_INTEGER_ARG( v0 );
   
    for(;;){
        OPT_INTEGER_ARG( vN );
        if( ! has_vN )break;
        if( !( v0 != vN ) ){ RESULT( mqo_vf_false( ) ); };
        v0 = vN;
    };

    RESULT( mqo_vf_true( ) );
MQO_END_PRIM( m_ne )

MQO_BEGIN_PRIM( "string=?", string_eqq )
    REQ_STRING_ARG( s0 );
    
    for(;;){
        OPT_STRING_ARG( sN );
        if( ! has_sN )break;
        if( mqo_string_compare( s0, sN ) ){ RESULT( mqo_vf_false( ) ); };
    };

    RESULT( mqo_vf_true( ) );
    NO_REST_ARGS( );
MQO_END_PRIM( string_eqq )

MQO_BEGIN_PRIM( "length", length )
    REQ_LIST_ARG( pair );
    NO_REST_ARGS( );
    INTEGER_RESULT( mqo_list_length( pair ) );
MQO_END_PRIM( length )

MQO_BEGIN_PRIM( "error-key", error_key )
    REQ_ERROR_ARG( err );
    NO_REST_ARGS( );
  
    RESULT( mqo_vf_symbol( err->key ) );
MQO_END_PRIM( error_key )

MQO_BEGIN_PRIM( "error-info", error_info )
    REQ_ERROR_ARG( err );
    NO_REST_ARGS( );
  
    RESULT( mqo_vf_pair( err->info ) );
MQO_END_PRIM( error_info )

MQO_BEGIN_PRIM( "error-context", error_context )
    REQ_ERROR_ARG( err );
    NO_REST_ARGS( );
  
    RESULT( mqo_vf_list( err->context ) );
MQO_END_PRIM( error_context )

MQO_BEGIN_PRIM( "map-car", map_car )
    REQ_LIST_ARG( src );
    NO_REST_ARGS( );
    mqo_tc tc = mqo_make_tc();
    while( src ){
        mqo_pair p = mqo_req_pair( mqo_car( src ) );
        mqo_tc_append( tc, mqo_car( p ) );
        src = mqo_req_list( mqo_cdr( src ) );
    }
    RESULT( mqo_car( tc ) );
MQO_END_PRIM( map_car );

MQO_BEGIN_PRIM( "map-cdr", map_cdr )
    REQ_LIST_ARG( src );
    NO_REST_ARGS( );
    mqo_tc tc = mqo_make_tc();
    while( src ){
        mqo_pair p = mqo_req_pair( mqo_car( src ) );
        mqo_tc_append( tc, mqo_cdr( p ) );
        src = mqo_req_list( mqo_cdr( src ) );
    }
    RESULT( mqo_car( tc ) );
MQO_END_PRIM( map_cdr );

MQO_BEGIN_PRIM( "thaw", thaw )
    REQ_STRING_ARG( src );
    NO_REST_ARGS( );
    RESULT( mqo_thaw_str( src ) );
MQO_END_PRIM( thaw );

MQO_BEGIN_PRIM( "freeze", freeze )
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    STRING_RESULT( mqo_freeze( value ) );
MQO_END_PRIM( freeze );

MQO_BEGIN_PRIM( "string-append", string_append )
    mqo_string s0 = mqo_make_string( 128 );
    for(;;){
        OPT_STRING_ARG( sN );
        if(! has_sN ) break;
        mqo_string_append( s0, mqo_sf_string( sN ), mqo_string_length( sN ) );
    }
    STRING_RESULT( s0 );
MQO_END_PRIM( string_append );

MQO_BEGIN_PRIM( "assq", assq )
    REQ_ANY_ARG( key );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    
    mqo_value v;

    while( list ){
        v = mqo_car( list );
        if( mqo_is_pair( v ) ){
        //TODO: Should this be an error?
            if( mqo_eqv( mqo_car( mqo_pair_fv( v ) ), key ) ){
                RESULT( v );
            }
        }
        //TODO: Should this be an error?
        list = mqo_list_fv( mqo_cdr( list ) );
    }

    RESULT( mqo_vf_false() );
MQO_END_PRIM( assq );

MQO_BEGIN_PRIM( "assoc", assoc )
    REQ_ANY_ARG( key );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );
    
    mqo_value v;

    while( list ){
        v = mqo_car( list );
        if( mqo_is_pair( v ) ){
        //TODO: Should this be an error?
            if( mqo_eq( mqo_car( mqo_pair_fv( v ) ), key ) ){
                RESULT( v );
            }
        }
        //TODO: Should this be an error?
        list = mqo_list_fv( mqo_cdr( list ) );
    }

    RESULT( mqo_vf_false() );
MQO_END_PRIM( assoc );

MQO_BEGIN_PRIM( "getcwd", getcwd )
    NO_REST_ARGS( );
    static char buf[ MAXPATHLEN ];
    if( getcwd( buf, MAXPATHLEN ) ){
        RESULT( mqo_vf_string( mqo_string_fs( buf ) ) );
    }else{
        mqo_errf( mqo_es_vm, "s", strerror( errno ) );
        NO_RESULT( );
    };
MQO_END_PRIM( getcwd )

MQO_BEGIN_PRIM( "chdir", chdir )
    REQ_STRING_ARG( path )
    NO_REST_ARGS( );
    
    mqo_os_error( chdir( mqo_sf_string( path ) ) );
    NO_RESULT( );
MQO_END_PRIM( chdir )

MQO_BEGIN_PRIM( "argv", argv )
    OPT_INTEGER_ARG( ix );
    NO_REST_ARGS( );
    if( has_ix ){
        if( ix < mqo_argc ){
            RESULT( mqo_car( mqo_list_ref( mqo_argv, ix ) ) );
        }else{
            RESULT( mqo_vf_false( ) );
        }
    }else{
        RESULT( mqo_vf_pair( mqo_argv ) );
    };
MQO_END_PRIM( argv )

MQO_BEGIN_PRIM( "argc", argc )
    NO_REST_ARGS( );
    RESULT( mqo_vf_integer( mqo_argc ) );
MQO_END_PRIM( argc )

MQO_BEGIN_PRIM( "refuse-method", refuse_method )
    mqo_errf( mqo_es_vm, "s", "method not found");
MQO_END_PRIM( refuse_method )

MQO_BEGIN_PRIM( "get-global", get_global )
    REQ_SYMBOL_ARG( symbol );
    OPT_ANY_ARG( def );
    NO_REST_ARGS( );

    if( mqo_has_global( symbol ) ){
        RESULT( mqo_get_global( symbol ) );
    }else if( has_def ){
        RESULT( def );
    }else{
        RESULT( mqo_vf_false() );
    }
MQO_END_PRIM( get_global )

MQO_BEGIN_PRIM( "enable-trace", enable_trace )
    NO_REST_ARGS( );
    if( mqo_trace_flag < 1000 )mqo_trace_flag += 1;
    NO_RESULT();
MQO_END_PRIM( enable_trace )

MQO_BEGIN_PRIM( "disable-trace", disable_trace )
    NO_REST_ARGS( );
    if( mqo_trace_flag )mqo_trace_flag -= 1;
    NO_RESULT();
MQO_END_PRIM( disable_trace )

MQO_BEGIN_PRIM( "make-tc", make_tc )
    REST_ARGS( seed );

    mqo_tc tc = mqo_make_tc( );

    if( seed ){
        mqo_set_car( tc, mqo_vf_pair( seed ) );
        mqo_set_cdr( tc, mqo_vf_pair( mqo_last_pair( seed ) ) );
    };

    TC_RESULT( tc );
MQO_END_PRIM( make_tc )

MQO_BEGIN_PRIM( "tc-clear!", tc_clear )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    mqo_set_car( tc, mqo_vf_null() );
    mqo_set_cdr( tc, mqo_vf_null() );
    TC_RESULT( tc );
MQO_END_PRIM( tc_clear )

MQO_BEGIN_PRIM( "tc-splice!", tc_splice )
    REQ_TC_ARG( tc );
    REQ_LIST_ARG( list );
    NO_REST_ARGS( );

    while( list ){
        mqo_tc_append( tc, mqo_car( list ) );
        list = mqo_req_list( mqo_cdr( list ) );
    }

    RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_splice )

MQO_BEGIN_PRIM( "tc-next!", tc_next )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    if( mqo_is_null( mqo_car( tc ) ) ){
        mqo_errf( mqo_es_vm, "s", "tconc out of items" );
    }
    mqo_pair next = mqo_list_fv( mqo_car( tc ) );
    mqo_pair lead = mqo_list_fv( mqo_cdr( next ) );
    if( lead ){
        mqo_set_car( tc, mqo_vf_pair( lead ) );
    }else{
        mqo_set_car( tc, mqo_vf_null() );
        mqo_set_cdr( tc, mqo_vf_null() );
    }
    RESULT( mqo_car( next ) );
MQO_END_PRIM( tc_next );

MQO_BEGIN_PRIM( "tc-empty?", tc_emptyq )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    RESULT( mqo_vf_boolean( mqo_is_null( mqo_car( tc ) ) ) );
MQO_END_PRIM( tc_emptyq );

MQO_BEGIN_PRIM( "tc-append!", tc_append )
    REQ_TC_ARG( tc );
    REQ_ANY_ARG( item );
    NO_REST_ARGS( );

    item = mqo_vf_pair( mqo_cons( item, mqo_vf_null() ) );

    if( mqo_is_null( mqo_car( tc ) ) ){
        mqo_set_car( tc, item );
    }else{
        mqo_set_cdr( mqo_pair_fv( mqo_cdr( tc ) ), item );
    };

    mqo_set_cdr( tc, item );
    RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_append )

MQO_BEGIN_PRIM( "tc-prepend!", tc_prepend )
    REQ_TC_ARG( tc );
    REQ_ANY_ARG( item );
    NO_REST_ARGS( );
    item = mqo_vf_pair( mqo_cons( item, mqo_car( tc ) ) );

    if( mqo_is_null( mqo_car( tc ) ) ){
        mqo_set_cdr( tc, item );
    };
    mqo_set_car( tc, item );

    RESULT( mqo_vf_tc( tc ) );
MQO_END_PRIM( tc_prepend )

MQO_BEGIN_PRIM( "tc->list", tc_to_list )
    REQ_TC_ARG( tc );
    NO_REST_ARGS( );
    RESULT( mqo_car( tc ) );
MQO_END_PRIM( tc_to_list )

mqo_symbol mqo_es_parse;
mqo_symbol mqo_es_inc;

MQO_BEGIN_PRIM( "string->exprs", string_to_exprs )
    REQ_STRING_ARG( src );
    NO_REST_ARGS( );
    
    mqo_boolean ok = 0;
    mqo_list v = mqo_parse_document( mqo_sf_string( src ), &ok );
    if( ok ){
        RESULT( mqo_vf_list( v ) );
    }else{
        mqo_errf( mqo_parse_incomplete ? mqo_es_inc :
                                         mqo_es_parse, 
                  "s", mqo_parse_errmsg 
        );
    }
MQO_END_PRIM( string_to_exprs )

MQO_BEGIN_PRIM( "globals", globals )
    NO_REST_ARGS( );
    RESULT( mqo_vf_list( mqo_get_globals( ) ) );
MQO_END_PRIM( globals );

MQO_BEGIN_PRIM( "set", set )
    mqo_set set = mqo_make_set( );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        mqo_tree_insert( set, item );
    }
    
    RESULT( mqo_vf_set( set ) );
MQO_END_PRIM( set )

MQO_BEGIN_PRIM( "set-add!", set_addd )
    REQ_SET_ARG( set );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        mqo_tree_insert( set, item );
    }
    
    RESULT( mqo_vf_set( set ) );
MQO_END_PRIM( set_addd )

MQO_BEGIN_PRIM( "set-remove!", set_removed )
    REQ_SET_ARG( set );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        mqo_tree_remove( set, item );
    }
    
    RESULT( mqo_vf_set( set ) );
MQO_END_PRIM( set_removed )

MQO_BEGIN_PRIM( "set-member?", set_memberq )
    REQ_SET_ARG( set );
    
    for(;;){
        OPT_ANY_ARG( item );
        if( ! has_item )break;
        if( ! mqo_tree_lookup( set, item ) ) FALSE_RESULT( );
    }
    
    TRUE_RESULT( );
MQO_END_PRIM( set_memberq )

MQO_BEGIN_PRIM( "set->list", set_to_list )
    REQ_SET_ARG( set );
    NO_REST_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    
    mqo_iter_tree( set, (mqo_iter_mt)mqo_untree_cb, tc );

    RESULT( mqo_car( tc ) );
MQO_END_PRIM( set_to_list )

MQO_BEGIN_PRIM( "dict", dict )
    mqo_dict dict = mqo_make_dict( );

    for(;;){
        OPT_PAIR_ARG( entry );
        if( ! has_entry )break;
        mqo_tree_insert( dict, mqo_vf_pair( entry ) );
    }
    
    RESULT( mqo_vf_dict( dict ) );
MQO_END_PRIM( dict )

MQO_BEGIN_PRIM( "dict->list", dict_to_list )
    REQ_DICT_ARG( dict );
    NO_REST_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    mqo_iter_tree( dict, (mqo_iter_mt)mqo_untree_cb, tc );
    
    RESULT( mqo_car( tc ) );
MQO_END_PRIM( dict_to_list )

void mqo_dict_keys_cb( mqo_value value, mqo_tc tc ){
    mqo_pair p = mqo_pair_fv( value );
    mqo_tc_append( tc, mqo_car( p ) );
}

MQO_BEGIN_PRIM( "dict-keys", dict_keys )
    REQ_DICT_ARG( dict );
    NO_REST_ARGS( );

    mqo_tc tc = mqo_make_tc( );

    mqo_iter_tree( dict, (mqo_iter_mt)mqo_dict_keys_cb, tc );
    
    RESULT( mqo_car( tc ) );
MQO_END_PRIM( dict_keys )

void mqo_dict_values_cb( mqo_value value, mqo_tc tc ){
    mqo_pair p = mqo_pair_fv( value );
    mqo_tc_append( tc, mqo_cdr( p ) );
}

MQO_BEGIN_PRIM( "dict-values", dict_values )
    REQ_DICT_ARG( dict );
    NO_REST_ARGS( );

    mqo_tc tc = mqo_make_tc( );
    
    mqo_iter_tree( dict, (mqo_iter_mt)mqo_dict_values_cb, tc );
    
    RESULT( mqo_car( tc ) );
MQO_END_PRIM( dict_values )

MQO_BEGIN_PRIM( "dict-set?", dict_setq )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( key );
    NO_REST_ARGS( );
    
    RESULT( mqo_tree_lookup( dict, key ) ? mqo_vf_true() : mqo_vf_false() );    
MQO_END_PRIM( dict_setq )

MQO_BEGIN_PRIM( "dict-set!", dict_setd )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( key );
    REQ_ANY_ARG( value );
    NO_REST_ARGS( );
    
    mqo_tree_insert( dict, mqo_vf_pair( mqo_cons( key, value ) ) );

    NO_RESULT();
MQO_END_PRIM( dict_setd )

MQO_BEGIN_PRIM( "dict-ref", dict_ref )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( key );
    OPT_ANY_ARG( alternate );
    NO_REST_ARGS( );
   
    mqo_node node = mqo_tree_lookup( dict, key );
    
    if( node ){
        RESULT( mqo_cdr( mqo_pair_fv( node->data ) ) );
    }else if( has_alternate ){
        RESULT( alternate );
    }else{
        RESULT( mqo_vf_false() );
    }
MQO_END_PRIM( dict_ref )

MQO_BEGIN_PRIM( "dict-remove!", dict_removed )
    REQ_DICT_ARG( dict );
    REQ_ANY_ARG( item );
    NO_REST_ARGS( );
    
    mqo_tree_remove( dict, item );
    
    NO_RESULT( );
MQO_END_PRIM( dict_removed )

char* mqo_memmem( const char* sp, mqo_integer sl, const char* ip, mqo_integer il ){
    // Like strstr, but \0-ignorant.
    if( sl < il )return NULL;

    sl = sl - il + 1;

    for( mqo_integer i = 0; i < sl; i ++ ){
        if( ! memcmp( sp, ip, il ) ) return (char*)sp;
        sp++;
    }

    return NULL;
}

MQO_BEGIN_PRIM( "string-find", string_find )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    const char* ip = mqo_memmem( sp, 
                                 mqo_string_length( string ), 
                                 mqo_sf_string( item ), 
                                 mqo_string_length( item ) );
    
    if( ip ){
        RESULT( mqo_vf_integer( ip - sp ) );
    }else{
        RESULT( mqo_vf_false( ) );
    }
MQO_END_PRIM( string_find )

MQO_BEGIN_PRIM( "string-begins-with?", string_begins_with )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    mqo_integer sl = mqo_string_length( string );
    mqo_integer il = mqo_string_length( item );

    if( sl < il ){
        RESULT( mqo_vf_false( ) );
    }else{
        const char* sp = mqo_sf_string( string );
        const char* ip = mqo_sf_string( item );

        RESULT( mqo_vf_boolean( ! memcmp( sp, ip, il ) ) );
    }
MQO_END_PRIM( string_begins_with )

MQO_BEGIN_PRIM( "strip", strip)
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    mqo_integer i, j, sl = mqo_string_length( string );
    const char* sp = mqo_sf_string( string );
    
    for( i = 0; i < sl; i ++ ){
        if( ! isspace( sp[i] ) ) break;
    }
    
    sp += i;
    sl -= i;

    while( sl ){
        if( ! isspace( sp[ sl - 1 ] ) )break;
        sl --;
    }
    
    RESULT( mqo_vf_string( mqo_string_fm( sp, sl ) ) );
MQO_END_PRIM( strip )

MQO_BEGIN_PRIM( "strip-head", strip_head )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    mqo_integer i, sl = mqo_string_length( string );
    const char* sp = mqo_sf_string( string );
    
    for( i = 0; i < sl; i ++ ){
        if( ! isspace( sp[i] ) ) break;
    }

    RESULT( mqo_vf_string(
        i ? mqo_string_fm( sp + i, sl - i ) : string
    ) );
MQO_END_PRIM( strip_head )

MQO_BEGIN_PRIM( "strip-tail", strip_tail )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    mqo_integer sl = mqo_string_length( string );
    const char* sp = mqo_sf_string( string );
  
    while( sl ){
        if( ! isspace( sp[ sl - 1 ] ) )break;
        sl --;
    }
    
    RESULT( mqo_vf_string( mqo_string_fm( sp, sl ) ) );
MQO_END_PRIM( strip_tail )

MQO_BEGIN_PRIM( "string-ends-with?", string_ends_with )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    mqo_integer sl = mqo_string_length( string );
    mqo_integer il = mqo_string_length( item );

    if( sl < il ){
        RESULT( mqo_vf_false( ) );
    }else{
        const char* sp = mqo_sf_string( string ) + sl - il;
        const char* ip = mqo_sf_string( item );

        RESULT( mqo_vf_boolean( ! memcmp( sp, ip, il ) ) );
    }
MQO_END_PRIM( string_ends_with )

MQO_BEGIN_PRIM( "split-lines", split_lines )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    
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

    RESULT( mqo_car( tc ) );
MQO_END_PRIM( split_lines )

MQO_BEGIN_PRIM( "string-split", string_split )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    mqo_integer sl = mqo_string_length( string );
    const char* ip = mqo_sf_string( item );
    mqo_integer il = mqo_string_length( item );
    const char* pp = mqo_memmem( sp, sl, ip, il );
    
    if( pp ){
        mqo_integer pl = pp - sp;
        item = mqo_string_fm( sp, pl );
        string = mqo_string_fm( pp + il, sl - il - pl );
        RESULT( 
                mqo_vf_pair( mqo_cons( mqo_vf_string( item ),
                             mqo_vf_pair( 
                                 mqo_cons( mqo_vf_string( string ),
                                           mqo_vf_null( ) ) ) ) ) );
    }else{
        RESULT( mqo_vf_pair( mqo_cons( mqo_vf_string( string ),
                                           mqo_vf_null( ) ) ) );
    }
MQO_END_PRIM( string_split )

MQO_BEGIN_PRIM( "string-replace", string_replace )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( pattern );
    REQ_STRING_ARG( replacement );
    NO_REST_ARGS( );
    
    const char* sp = mqo_sf_string( string );
    mqo_integer sl = mqo_string_length( string );

    const char* ip = mqo_sf_string( pattern );
    mqo_integer il = mqo_string_length( pattern );
    
    const char* rp = mqo_sf_string( replacement );
    mqo_integer rl = mqo_string_length( replacement );
    
    mqo_tc tc = mqo_make_tc( );
    const char* pp;
 
    mqo_string buf = mqo_make_string( sl );
    while( pp = mqo_memmem( sp, sl, ip, il ) ){
        mqo_integer pl = pp - sp;
        mqo_string_append( buf, sp, pl );
        mqo_string_append( buf, rp, rl );
        sl = sl - pl - il;
        sp = sp + pl + il;
    }
   
    mqo_string_append( buf, sp, sl );
    
    STRING_RESULT( buf );
MQO_END_PRIM( string_replace )

MQO_BEGIN_PRIM( "string-split*", string_splitm )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( item );
    NO_REST_ARGS( );
    
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

    RESULT( mqo_car( tc ) );
MQO_END_PRIM( string_splitm )

MQO_BEGIN_PRIM( "string-join", string_join )
    // Most languages use join( list, sep ), but in Lisp, it's always nice
    // to ensure that the list argument is last, to permit the use and
    // abuse of Apply, e.g.
    //
    // (apply string-join ", " items)
    
    REQ_STRING_ARG( sep );

    mqo_string res = mqo_make_string( 128 );
    int any = 0;

    for(;;){
        OPT_STRING_ARG( item );
        if( ! has_item ) break;
        if( any ){
            mqo_string_append( res, mqo_sf_string( sep ), 
                                    mqo_string_length( sep ) );
        }
        any = 1;
        mqo_string_append( res, mqo_sf_string( item ), 
                                mqo_string_length( item ) );
    }
    
    RESULT( mqo_vf_string( res ) );
MQO_END_PRIM( string_join )

MQO_BEGIN_PRIM( "function?", functionq )
    REQ_ANY_ARG( value )
    NO_REST_ARGS( );

    BOOLEAN_RESULT( mqo_is_function( value ) );
MQO_END_PRIM( functionq )

MQO_BEGIN_PRIM( "function-name", function_name )
    REQ_ANY_ARG( function )
    NO_REST_ARGS( );

    RESULT( mqo_function_name( function ) );
MQO_END_PRIM( function_name )

MQO_BEGIN_PRIM( "make-string", make_string )
    OPT_INTEGER_ARG( capacity );
    NO_REST_ARGS( );
    
    if( ! has_capacity ){ 
        capacity = 1024; 
    }else if( capacity < 0 ){
        mqo_errf( mqo_es_vm, "sx", "expected non-negative", capacity );
    }

    mqo_string string = mqo_make_string( capacity );

    RESULT( mqo_vf_string( string ) );
MQO_END_PRIM( make_string )

MQO_BEGIN_PRIM( "flush-string", flush_string )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );

    mqo_string_flush( string );
    NO_RESULT( );
MQO_END_PRIM( flush_string )

MQO_BEGIN_PRIM( "empty-string?", empty_stringq )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );

    RESULT( mqo_vf_boolean( mqo_string_empty( string ) ) );
MQO_END_PRIM( string_empty )

MQO_BEGIN_PRIM( "string-skip-space", string_skip_space )
    REQ_STRING_ARG( string );
    NO_REST_ARGS( );
    
    mqo_quad ix, len = mqo_string_length( string );
    const char* str = mqo_sf_string( string );
   
    for( ix = 0; ix < len; ix ++ ){
        if( ! isspace( str[ix] ) )break;
    }
    
    if( ix )mqo_string_skip( string, ix );
    
    NO_RESULT( );
MQO_END_PRIM( string_skip_space );

MQO_BEGIN_PRIM( "string-skip", string_skip )
    REQ_STRING_ARG( string );
    REQ_INTEGER_ARG( offset );
    NO_REST_ARGS( );
    if( offset > mqo_string_length( string ) ){
        mqo_errf( mqo_es_vm, "s", "skip past end of string" );
    }
    mqo_string_skip( string, offset );
    NO_RESULT( );
MQO_END_PRIM( string_skip );

MQO_BEGIN_PRIM( "string-read!", string_read )
    REQ_STRING_ARG( string );
    OPT_INTEGER_ARG( max );
    NO_REST_ARGS( );
    if( ! has_max ) max = mqo_string_length( string );
    void* data = mqo_string_read( string, &max );
    if( max == 0 ){
        RESULT( mqo_vf_false( ) );
    }else{
        RESULT( mqo_vf_string( mqo_string_fm( data, max ) ) );
    }
MQO_END_PRIM( string_read );

MQO_BEGIN_PRIM( "string-append-byte!", string_append_byte )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( byte )
    NO_REST_ARGS( );
    
    if(!( 0<= byte <= 255 )){
        mqo_errf( mqo_es_vm, "sx", "expected data to be in [0,255]",
                  byte );
    }
    mqo_byte data = byte;
    mqo_string_append( string, &data, sizeof( mqo_byte ) );

    NO_RESULT( );
MQO_END_PRIM( string_append_byte )

MQO_BEGIN_PRIM( "string-read-byte!", string_read_byte )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    mqo_integer read = sizeof( mqo_byte );

    if( mqo_string_length( string ) < read ){
        RESULT( mqo_vf_false( ) );
    }
    
    mqo_byte* data = mqo_string_read( string, &read ); 

    RESULT( mqo_vf_integer( *data ) );
MQO_END_PRIM( string_read_byte )

MQO_BEGIN_PRIM( "string-read-line!", string_read_line )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    mqo_integer linelen; 
    const char* line = mqo_string_read_line( string, &linelen ); 
    
    RESULT( line ? mqo_vf_string( mqo_string_fm( line, linelen ) ) 
                     : mqo_vf_false( ) );
MQO_END_PRIM( string_read_line )

MQO_BEGIN_PRIM( "string-append-word!", string_append_word )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( word )
    NO_REST_ARGS( );
    
    if(!( 0<= word <= 65535 )){
        mqo_errf( mqo_es_vm, "sx", "expected data to be in [0,65535]",
                  word );
    }
    
    mqo_string_append_word( string, word );

    NO_RESULT( );
MQO_END_PRIM( string_append_word )

MQO_BEGIN_PRIM( "string-read-word!", string_read_word )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    mqo_integer read = sizeof( mqo_word );

    if( mqo_string_length( string ) < read ){
        RESULT( mqo_vf_false( ) );
    }
    
    mqo_word* data = mqo_string_read( string, &read ); 

    RESULT( mqo_vf_integer( ntohs( *data ) ) );
MQO_END_PRIM( string_read_word )

MQO_BEGIN_PRIM( "string-append-quad!", string_append_quad )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( quad )
    NO_REST_ARGS( );
    
    mqo_string_append_quad( string, quad );

    NO_RESULT( );
MQO_END_PRIM( string_append_quad )

MQO_BEGIN_PRIM( "string-read-quad!", string_read_quad )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( );
    
    mqo_integer read = sizeof( mqo_quad );

    if( mqo_string_length( string ) < read ){
        RESULT( mqo_vf_false( ) );
    }
    
    mqo_quad* data = mqo_string_read( string, &read ); 

    RESULT( mqo_vf_integer( ntohl( *data ) ) );
MQO_END_PRIM( string_read_quad )

MQO_BEGIN_PRIM( "string-alter!", string_alterd )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( offset )
    REQ_INTEGER_ARG( length )
    REQ_STRING_ARG( data )
    NO_REST_ARGS( )
    
    if(( offset + length ) > mqo_string_length( string ) ){
        mqo_errf( mqo_es_vm, "s", "replaced portion not within string" );
    }

    mqo_string_alter( string, offset, length, 
                      mqo_sf_string( data ), mqo_string_length( data ) );
    
    NO_RESULT( );
MQO_END_PRIM( string_alterd )

MQO_BEGIN_PRIM( "string-prepend!", string_prependd )
    REQ_STRING_ARG( string )
    REQ_ANY_ARG( data )
    NO_REST_ARGS( )
    
    void* src; mqo_integer srclen;

    if( mqo_is_string( data ) ){
        mqo_string str = mqo_string_fv( data );
        src = mqo_sf_string( str );
        srclen = mqo_string_length( str );
    }else if( mqo_is_integer( data ) ){
        mqo_integer x = mqo_integer_fv( data );
        src = &x;
        srclen = 1;
    }

    mqo_string_prepend( string, src, srclen );
    
    NO_RESULT( );
MQO_END_PRIM( string_prependd )

MQO_BEGIN_PRIM( "append", append )
    mqo_tc tc = mqo_make_tc( );

    for(;;){
        OPT_LIST_ARG( list );
        if( ! has_list )break;
        while( list ){
            mqo_tc_append( tc, mqo_car( list ) );
            list = mqo_req_list( mqo_cdr( list ) );
        }
    }

    RESULT( mqo_car( tc ) );
MQO_END_PRIM( append )

MQO_BEGIN_PRIM( "string-append!", string_appendd )
    REQ_STRING_ARG( string )
    REQ_ANY_ARG( data )
    NO_REST_ARGS( )
    
    void* src; mqo_integer srclen;

    if( mqo_is_string( data ) ){
        mqo_string str = mqo_string_fv( data );
        src = mqo_sf_string( str );
        srclen = mqo_string_length( str );
    }else if( mqo_is_integer( data ) ){
        mqo_integer x = mqo_integer_fv( data );
        src = &x;
        srclen = 1;
    }

    mqo_string_append( string, src, srclen );
    
    NO_RESULT( );
MQO_END_PRIM( string_appendd )

MQO_BEGIN_PRIM( "string-erase!", string_erased )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( offset )
    REQ_INTEGER_ARG( length )
    NO_REST_ARGS( )
    
    if(( offset + length ) > mqo_string_length( string ) ){
        mqo_errf( mqo_es_vm, "s", "erased portion not within string" );
    }

    mqo_string_alter( string, offset, length, NULL, 0 );
    
    NO_RESULT( );
MQO_END_PRIM( string_erased )

MQO_BEGIN_PRIM( "string-insert!", string_insertd )
    REQ_STRING_ARG( string )
    REQ_INTEGER_ARG( offset )
    REQ_ANY_ARG( data )
    NO_REST_ARGS( )
    
    void* src; mqo_integer srclen;

    if( mqo_is_string( data ) ){
        mqo_string str = mqo_string_fv( data );
        src = mqo_sf_string( str );
        srclen = mqo_string_length( str );
    }else if( mqo_is_integer( data ) ){
        mqo_integer x = mqo_integer_fv( data );
        src = &x;
        srclen = 1;
    }

    if( offset > mqo_string_length( string ) ){
        mqo_errf( mqo_es_vm, "s", "insertion past end of string" );
    }

    mqo_string_alter( string, offset, 0, src, srclen );
    
    NO_RESULT( );
MQO_END_PRIM( string_insertd )

MQO_BEGIN_PRIM( "copy-string", copy_string )
    REQ_STRING_ARG( string )
    NO_REST_ARGS( )

    mqo_string new = mqo_string_fm( mqo_sf_string( string ),
                                    mqo_string_length( string ) );

    RESULT( mqo_vf_string( new ) );
MQO_END_PRIM( copy_string )

void mqo_bind_core_prims( ){
    MQO_BIND_PRIM( integerq );
    MQO_BIND_PRIM( listq );
    MQO_BIND_PRIM( cons );
    MQO_BIND_PRIM( car );
    MQO_BIND_PRIM( cdr );
    MQO_BIND_PRIM( cadr );
    MQO_BIND_PRIM( caddr );
    MQO_BIND_PRIM( set_car );
    MQO_BIND_PRIM( set_cdr );
    MQO_BIND_PRIM( length );
    MQO_BIND_PRIM( make_vector );
    MQO_BIND_PRIM( vector );
    MQO_BIND_PRIM( vector_set );
    MQO_BIND_PRIM( vector_ref );
    MQO_BIND_PRIM( vector_length );
    MQO_BIND_PRIM( eq );
    MQO_BIND_PRIM( equal );
    MQO_BIND_PRIM( memq );
    MQO_BIND_PRIM( member );
    MQO_BIND_PRIM( assoc );
    MQO_BIND_PRIM( assq );
    MQO_BIND_PRIM( string_append );
    MQO_BIND_PRIM( string_length );
    MQO_BIND_PRIM( string_ref );
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
    MQO_BIND_PRIM( reverse );    
    MQO_BIND_PRIM( reversed );    

    // Extensions to R5RS
    MQO_BIND_PRIM( map_car );
    MQO_BIND_PRIM( map_cdr );

    MQO_BIND_PRIM( thaw );
    MQO_BIND_PRIM( freeze );
    MQO_BIND_PRIM( getcwd );
    MQO_BIND_PRIM( chdir );
    MQO_BIND_PRIM( argv );
    MQO_BIND_PRIM( argc );

    MQO_BIND_PRIM( refuse_method );

    MQO_BIND_PRIM( get_global );
    
    MQO_BIND_PRIM( enable_trace );
    MQO_BIND_PRIM( disable_trace );

    MQO_BIND_PRIM( make_tc );
    MQO_BIND_PRIM( tc_splice );
    MQO_BIND_PRIM( tc_append );
    MQO_BIND_PRIM( tc_prepend );
    MQO_BIND_PRIM( tc_to_list );
    MQO_BIND_PRIM( tc_next );
    MQO_BIND_PRIM( tc_emptyq );
    MQO_BIND_PRIM( tc_clear );

    MQO_BIND_PRIM( string_to_exprs );

    MQO_BIND_PRIM( set );
    MQO_BIND_PRIM( set_addd );
    MQO_BIND_PRIM( set_removed );
    MQO_BIND_PRIM( set_memberq );
    MQO_BIND_PRIM( set_to_list );
    
    MQO_BIND_PRIM( dict );
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
    
    MQO_BIND_PRIM( globals );
    MQO_BIND_PRIM( function_name );
    MQO_BIND_PRIM( functionq );

    MQO_BIND_PRIM( make_string );
    MQO_BIND_PRIM( flush_string );
    MQO_BIND_PRIM( empty_stringq );
    MQO_BIND_PRIM( string_append );
    MQO_BIND_PRIM( string_read );
    MQO_BIND_PRIM( string_read_line );
    MQO_BIND_PRIM( string_append_byte );
    MQO_BIND_PRIM( string_read_byte );
    MQO_BIND_PRIM( string_append_word );
    MQO_BIND_PRIM( string_read_word );
    MQO_BIND_PRIM( string_append_quad );
    MQO_BIND_PRIM( string_read_quad );
    MQO_BIND_PRIM( string_skip );

    MQO_BIND_PRIM( append );
    MQO_BIND_PRIM( substring );
    MQO_BIND_PRIM( string_head );
    MQO_BIND_PRIM( string_tail );

    MQO_BIND_PRIM( string_to_integer )
    MQO_BIND_PRIM( string_replace )
    
    MQO_BIND_PRIM( strip_head );
    MQO_BIND_PRIM( strip_tail );
    MQO_BIND_PRIM( strip );
    MQO_BIND_PRIM( string_skip_space );
    
    MQO_BIND_PRIM( string_alterd );
    MQO_BIND_PRIM( string_prependd );
    MQO_BIND_PRIM( string_appendd );
    MQO_BIND_PRIM( string_insertd );
    MQO_BIND_PRIM( string_erased );
    
    MQO_BIND_PRIM( copy_string );
    
    MQO_BIND_PRIM( error_key );
    MQO_BIND_PRIM( error_info );

MQO_BIND_PRIM( xml_escape );
MQO_BIND_PRIM( percent_encode );
MQO_BIND_PRIM( percent_decode );

    mqo_es_parse = mqo_symbol_fs( "parse" );
    mqo_root_obj( (mqo_object) mqo_es_parse );
    mqo_es_inc = mqo_symbol_fs( "inc" );
    mqo_root_obj( (mqo_object) mqo_es_inc );
}
