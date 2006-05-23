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

#ifndef MQO_CLOSURE_H
#define MQO_CLOSURE_H 1

#include "memory.h"
#include "procedure.h"

MQO_BEGIN_TYPE( closure )
    mqo_value     name;
    mqo_instruction inst;
    mqo_pair      env;
MQO_END_TYPE( closure )

#define REQ_CLOSURE_ARG( vn ) REQ_TYPED_ARG( vn, closure )
#define CLOSURE_RESULT( vn ) TYPED_RESULT( vn, closure )
#define OPT_CLOSURE_ARG( vn ) OPT_TYPED_ARG( vn, closure )

static inline mqo_value mqo_clos_name( mqo_closure clos ){ 
    return clos->name;
}
static inline mqo_instruction mqo_clos_inst( mqo_closure clos ){
    return clos->inst;
}
static inline mqo_pair mqo_clos_env( mqo_closure clos ){
    return clos->env;
}

mqo_closure mqo_make_closure( mqo_instruction inst, mqo_pair env );
mqo_value mqo_function_name( mqo_value function );

void mqo_init_closure_subsystem( );

#endif
