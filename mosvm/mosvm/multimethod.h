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

#ifndef MQO_MULTIMETHOD_H
#define MQO_MULTIMETHOD_H 1

#include "memory.h"

MQO_BEGIN_TYPE( multimethod )
    mqo_value     signature;
    mqo_value     func;
    mqo_value     next;
    mqo_value     name;
MQO_END_TYPE( multimethod )

#define REQ_MULTIMETHOD_ARG( vn ) REQ_TYPED_ARG( vn, multimethod )
#define MULTIMETHOD_RESULT( vn ) TYPED_RESULT( multimethod, vn )
#define OPT_MULTIMETHOD_ARG( vn ) OPT_TYPED_ARG( vn, multimethod )

mqo_multimethod mqo_make_multimethod( 
    mqo_value signature, mqo_value func, mqo_value next
);
mqo_value mqo_reduce_function( mqo_value func, mqo_list args );

void mqo_init_multimethod_subsystem( );

#endif
