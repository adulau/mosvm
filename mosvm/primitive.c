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
 * along with this library; if not, print to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#include "mosvm.h"

mqo_primitive mqo_make_primitive( const char* name, mqo_prim_fn impl ){
    mqo_symbol sym = mqo_symbol_fs( name );
    mqo_primitive prim = MQO_OBJALLOC( primitive );
    prim->name = sym;
    prim->impl = impl;
    prim->code = prim->a = prim->b = 0;
    return prim;
}
void mqo_bind_primitive( const char* name, mqo_prim_fn impl ){
    mqo_primitive prim = mqo_make_primitive( name, impl );
    mqo_set_global( prim->name, mqo_vf_primitive( prim ) );
}
void mqo_trace_primitive( mqo_primitive prim ){
    mqo_grey_obj( (mqo_object) mqo_prim_name( prim ) );
}
void mqo_format_primitive( mqo_string buf, mqo_primitive prim ){
    mqo_format_begin( buf, prim );
    mqo_format_char( buf, ' ' );
    mqo_format_sym( buf, mqo_prim_name( prim ) );
    mqo_format_end( buf );
}

mqo_pair mqo_arg_ptr = NULL;
mqo_integer mqo_arg_ct = 0;

void mqo_no_more_args( ){
    if( mqo_arg_ptr != NULL ){
        mqo_errf( mqo_es_vm, "s", "expected no more arguments" );
    }
}

MQO_GENERIC_COMPARE( primitive );
MQO_GENERIC_FREE( primitive );
MQO_C_TYPE( primitive );

void mqo_init_primitive_subsystem( ){
    MQO_I_TYPE( primitive );
}

