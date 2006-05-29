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

mqo_closure mqo_make_closure( mqo_value name, mqo_instruction inst, mqo_pair env ){
    mqo_closure clos = MQO_OBJALLOC( closure );
    clos->inst = inst;
    clos->env = env;
    clos->name = name;
    return clos;
}

void mqo_trace_closure( mqo_closure clos ){
    mqo_grey_val( mqo_clos_name( clos ) );
    mqo_grey_obj( (mqo_object) mqo_clos_inst( clos )->proc );
    mqo_grey_obj( (mqo_object) mqo_clos_env( clos ) );
}

void mqo_format_closure( mqo_string buf, mqo_closure clos ){
    mqo_format_begin( buf, clos );
    mqo_format_char( buf, ' ' );
    mqo_format( buf, mqo_closure->name );
    mqo_format_end( buf );
}

mqo_value mqo_function_name( mqo_value function ){
    mqo_value result;

    if( mqo_is_closure( function ) ){
        result = mqo_closure_fv( function )->name;
        if( ! result ) result = function;
    }else if( mqo_is_multimethod( function ) ){
        result = mqo_multimethod_fv( function )->name;
    }else if( mqo_is_primitive( function ) ){
        result = mqo_vf_symbol( mqo_primitive_fv( function )->name );
    }else{
        result = function;
    }

    return result;
}

MQO_GENERIC_COMPARE( closure );
MQO_GENERIC_FREE( closure );
MQO_C_TYPE( closure );

void mqo_init_closure_subsystem( ){
    MQO_I_TYPE( closure );
}

