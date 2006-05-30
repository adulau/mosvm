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

mqo_multimethod mqo_make_multimethod( 
    mqo_value signature, mqo_value func, mqo_value next
){
    mqo_multimethod m = MQO_OBJALLOC( multimethod );
    m->signature = signature;
    m->func = func;
    m->next = next;
    m->name = mqo_function_name( func );
    return m;
}

void mqo_trace_multimethod( mqo_multimethod m ){
    mqo_grey_val( m->signature );
    mqo_grey_val( m->func );
    mqo_grey_val( m->next );
    mqo_grey_val( m->name );
}

mqo_boolean mqo_isa( mqo_value x, mqo_value t ){
    if( mqo_is_type( t ) ){
        return mqo_type_fv( t ) == mqo_direct_type( x );
    }else if( mqo_is_cell( x ) ){
        return mqo_cell_fv( x )->tag == mqo_tag_fv( t );
    }else{
        return 0;
    }
}

mqo_value mqo_reduce_function( mqo_value fn, mqo_list args ){
    if(! mqo_is_multimethod( fn ) )return fn;
    mqo_multimethod mm = mqo_multimethod_fv( fn );
    mqo_value arg, sig, sigs = mm->signature;
    for(;;){
        if( mqo_is_true( sigs ) )return mm->func;
        if( mqo_is_null( sigs ) )return args ? mm->next : mm->func;
        if( ! args )return mm->next;
        sig = mqo_car( mqo_pair_fv( sigs ) );
        sigs = mqo_cdr( mqo_pair_fv( sigs ) );
        arg = mqo_car( ( args ) );
        args = mqo_list_fv( mqo_cdr( args ) );
        if( ! mqo_isa( arg, sig ) ) return mm->next;
    }
}

void mqo_format_multimethod( mqo_string buf, mqo_multimethod multimethod ){
    mqo_format_begin( buf, multimethod );
    mqo_format_char( buf, ' ' );
    mqo_format( buf, multimethod->name );
    mqo_format_end( buf );
}

MQO_GENERIC_FREE( multimethod );
MQO_GENERIC_COMPARE( multimethod );

MQO_C_TYPE( multimethod );

MQO_BEGIN_PRIM( "make-multimethod", make_multimethod )
    REQ_ANY_ARG( sig );
    REQ_ANY_ARG( pass );
    REQ_ANY_ARG( fail );
    NO_REST_ARGS( );

    if((! mqo_is_true( sig ))&&(! mqo_is_pair( sig ) )){
        mqo_errf( mqo_es_vm, "sx", "expected list or #t", sig );
    };

    if(! mqo_is_function( fail ) ){
        mqo_errf( mqo_es_vm, "sx", "expected function for fail", fail );
    };

    if(! mqo_is_function( pass ) ){
        mqo_errf( mqo_es_vm, "sx", "expected function for pass", pass );
    };
    
    MULTIMETHOD_RESULT( mqo_make_multimethod( sig, pass, fail ) );
MQO_END_PRIM( make_multimethod )

MQO_BEGIN_PRIM( "isa?", isaq )
    REQ_ANY_ARG( value );
    REQ_ANY_ARG( type );
    NO_REST_ARGS( );
    
    if( mqo_is_type( type ) || mqo_is_tag( type ) ){
        BOOLEAN_RESULT( mqo_isa( value, type ) );
    }else{
        FALSE_RESULT( );
    }
MQO_END_PRIM( isaq );

void mqo_init_multimethod_subsystem( ){
    MQO_I_TYPE( multimethod );
    MQO_BIND_PRIM( make_multimethod );
    MQO_BIND_PRIM( isaq );
}
