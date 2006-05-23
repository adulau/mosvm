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

#ifndef MQO_PRIMITIVE_H
#define MQO_PRIMITIVE_H 1

#include "memory.h"

typedef void (*mqo_prim_fn)();

MQO_BEGIN_TYPE( primitive )
    mqo_symbol  name;
    mqo_prim_fn impl;
    mqo_byte    code, a, b; // Only used for instructions.
MQO_END_TYPE( primitive )

#define REQ_PRIMITIVE_ARG( vn ) REQ_TYPED_ARG( vn, primitive )
#define PRIMITIVE_RESULT( vn ) TYPED_RESULT( vn, primitive )
#define OPT_PRIMITIVE_ARG( vn ) OPT_TYPED_ARG( vn, primitive )

static inline mqo_symbol mqo_prim_name( mqo_primitive prim ){ 
    return prim->name;
}
static inline mqo_prim_fn mqo_prim_impl( mqo_primitive prim ){
    return prim->impl;
}

mqo_primitive mqo_make_primitive( const char* name, mqo_prim_fn impl );
void mqo_bind_primitive( const char* name, mqo_prim_fn impl );

extern mqo_pair mqo_arg_ptr;
extern mqo_integer mqo_arg_ct;

#define MQO_BIND_PRIM( pn ) \
    mqo_bind_primitive( mqo_prim_##pn##_name, mqo_prim_##pn );

#define MQO_BEGIN_PRIM( ln, pn ) \
    const char* mqo_prim_##pn##_name = ln; \
    void mqo_prim_##pn( ){

#define MQO_END_PRIM( pn ) };

#define REST_ARGS( vn ) mqo_pair vn = mqo_arg_ptr;
#define NO_REST_ARGS( vn ) mqo_no_more_args( );

void mqo_init_primitive_subsystem( );

#endif
