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

void mqo_format_number( mqo_string buf, mqo_value v ){
    mqo_format_int( buf, mqo_integer_fv( v ) );
}

mqo_integer mqo_number_compare( mqo_value a, mqo_value b ){
    return mqo_integer_fv( a ) - mqo_integer_fv( b );
}

MQO_GENERIC_GC( number );
MQO_C_TYPE( number );

mqo_number mqo_nf_integer( mqo_integer x ){
    mqo_number io = MQO_OBJALLOC( number );
    io->intval = x;
    return io;
}
mqo_integer mqo_integer_fn( mqo_number x ){
    return x->intval;
}
mqo_integer mqo_integer_fv( mqo_value x ){
    assert( mqo_is_number( x ) || mqo_is_imm( x ) );

    if( mqo_is_imm( x ) ){
        return mqo_imm_fv( x );
    }else{
        return mqo_integer_fn( (mqo_number)mqo_obj_fv( x ) );
    }
}
mqo_value mqo_vf_integer( mqo_integer x ){
    if(( x < 0 )||( x > MQO_MAX_IMM )){
        return mqo_vf_number( mqo_nf_integer( x ) );
    }else{
        return mqo_vf_imm( x );
    }
}
mqo_boolean mqo_is_integer( mqo_value x ){
    return mqo_is_number( x );
}
mqo_boolean mqo_is_number( mqo_value x ){
    return mqo_is_imm( x ) || ( mqo_obj_type( mqo_obj_fv( x ) ) == mqo_number_type );
}
mqo_integer mqo_req_integer( mqo_value x ){
    if( mqo_is_imm( x ) ){ 
        return mqo_imm_fv( x ); 
    }else if( mqo_is_number( x ) ){
        return mqo_integer_fn( (mqo_number)mqo_obj_fv( x ) );
    }else{
        mqo_errf( mqo_es_vm, "sx", "expected integer", x );
    }
}
mqo_integer mqo_req_intarg( ){
    return mqo_req_integer( mqo_req_any( ) ); 
}
mqo_integer mqo_opt_intarg( mqo_boolean* has ){
    mqo_value x = mqo_opt_any( has );
    if( *has ) return mqo_req_integer( x );
}

MQO_BEGIN_PRIM( "+", plus )
    REQ_INTEGER_ARG( sum );
    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        sum += x;
    }
    INTEGER_RESULT( sum );
MQO_END_PRIM( plus )

MQO_BEGIN_PRIM( "-", minus )
    REQ_INTEGER_ARG( base );

    int any = 0;

    for(;;){
        OPT_INTEGER_ARG( x );
        if( ! has_x )break;
        any = 1;
        base -= x;
    };

    INTEGER_RESULT( any ? base : - base );
MQO_END_PRIM( minus )

void mqo_init_number_subsystem( ){
    MQO_I_TYPE( number );
    MQO_BIND_PRIM( plus );
    MQO_BIND_PRIM( minus );
    mqo_set_global( 
        mqo_symbol_fs( "*max-int*" ), mqo_vf_integer( MQO_MAX_INT ) );
    mqo_set_global( 
        mqo_symbol_fs( "*max-imm*" ), mqo_vf_integer( MQO_MAX_IMM ) );
    mqo_set_global( 
        mqo_symbol_fs( "*min-int*" ), mqo_vf_integer( MQO_MIN_INT ) );
    mqo_set_global( 
        mqo_symbol_fs( "*min-imm*" ), mqo_vf_integer( MQO_MIN_IMM ) );
}
