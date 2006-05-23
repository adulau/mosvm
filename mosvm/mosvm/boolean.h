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

#ifndef MQO_BOOLEAN_H
#define MQO_BOOLEAN_H 1

#include "memory.h"

extern mqo_value mqo_the_true;
extern mqo_value mqo_the_false;

MQO_H_TP( boolean );
MQO_H_IS( boolean );
#define REQ_BOOLEAN_ARG( vn ) REQ_TYPED_ARG( vn, boolean )
#define BOOLEAN_RESULT( vn ) TYPED_RESULT( boolean, vn )
#define OPT_TYPE_ARG( vn ) OPT_TYPED_ARG( vn, type )

static inline mqo_value mqo_vf_false( ){ return mqo_the_false; }
static inline mqo_value mqo_vf_true( ){ return mqo_the_true; }
static inline mqo_value mqo_vf_boolean( mqo_boolean q ){
    return q ? mqo_the_true : mqo_the_false;
}
static inline mqo_boolean mqo_is_false( mqo_value v ){
    return v == mqo_the_false;
}
static inline mqo_boolean mqo_is_true( mqo_value v ){
    return v == mqo_the_true;
}

void mqo_init_boolean_subsystem( );

#endif
