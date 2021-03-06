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
#include <setjmp.h>
#include <stdarg.h>

mqo_quad mqo_vm_count = 0;
mqo_process mqo_first_enabled = NULL;
mqo_process mqo_last_enabled = NULL;
mqo_process mqo_active_process = NULL;

void mqo_activate_vm( mqo_process process, mqo_vm vm );
void mqo_activate_netmon( mqo_process process, mqo_object );

MQO_GENERIC_FORMAT( process );
MQO_GENERIC_FREE( process );
MQO_GENERIC_COMPARE( process );
void mqo_trace_actives( ){
    mqo_grey_obj( (mqo_object) mqo_first_enabled );
}

mqo_process mqo_make_process( 
    mqo_proc_fn activate, mqo_proc_fn deactivate, mqo_value context 
){
    mqo_process process = MQO_OBJALLOC( process );
    process->activate = activate;
    process->deactivate = deactivate;
    process->context = context;
    process->prev = process->next = NULL;
    process->enabled = 0;
    process->monitoring = NULL;
    if( mqo_active_process ){
        process->input = mqo_active_process->input;
        process->output = mqo_active_process->output;
    }else{
        process->input = NULL;
        process->output = NULL;
    };
    return process;
}

mqo_vm mqo_make_vm( ){
    mqo_vm vm = MQO_OBJALLOC( vm );
    return vm;
}

mqo_object mqo_process_input( mqo_process process ){
    return process->input;
}
mqo_object mqo_process_output( mqo_process process ){
    return process->output;
}
void mqo_set_process_input( mqo_process process, mqo_object input ){
    process->input = input;
}
void mqo_set_process_output( mqo_process process, mqo_object output ){
    process->output = output;
}
void mqo_enable_process( mqo_process process ){
    if( process->enabled )return; 
    
    if( mqo_is_vm( process->context ) ) mqo_vm_count ++;

    process->enabled = 1;
    process->next = NULL;
    process->prev = mqo_last_enabled;

    if( mqo_last_enabled ){
        mqo_last_enabled->next = process;
        mqo_last_enabled = process;
    }else{
        mqo_first_enabled = process;
        mqo_last_enabled = process;
    }
}

void mqo_disable_process( mqo_process process ){
    if( ! process->enabled )return; 

    if( mqo_is_vm( process->context ) ) mqo_vm_count --;

    mqo_process prev = process->prev;
    mqo_process next = process->next;
    process->enabled = 0;
   
    if( prev ){
        prev->next = next;
    }else{
        mqo_first_enabled = next;
    };

    if( next ){
        next->prev = prev;
    }else{
        mqo_last_enabled = prev;
    }
    
    process->next = process->prev = NULL;
}

void mqo_proc_loop( ){
    if( mqo_proc_xp ){
        // This means a subordinate process tried to return to the proc loop;
        // we kill the interpreter exit point, then rejoin the proc loop.
        mqo_interp_xp = NULL;

        if( mqo_active_process ){
            mqo_active_process->deactivate( (mqo_object) mqo_active_process,
                                            mqo_active_process->context );
        }
            
        longjmp( *mqo_proc_xp, 101 );
    }

    jmp_buf exit; 
    mqo_proc_xp = &exit;
    setjmp( exit ); 

    while( mqo_first_enabled ){
        mqo_active_process = mqo_first_enabled;
        while( mqo_active_process ){
            mqo_active_process->activate( (mqo_object) mqo_active_process,
                                          mqo_active_process->context );
            mqo_active_process->deactivate( (mqo_object) mqo_active_process,
                                            mqo_active_process->context );
            mqo_active_process = mqo_active_process->next;
        }
    }

    mqo_proc_xp = NULL;
}

void mqo_load_vm( mqo_vm vm ){
    MQO_IP = vm->ip;
    MQO_AP = vm->ap;
    MQO_CP = vm->cp;
    MQO_EP = vm->ep;
    MQO_GP = vm->gp;
    MQO_RX = vm->rx;
}

void mqo_save_vm( mqo_vm vm ){
    vm->ip = MQO_IP;
    vm->ap = MQO_AP;
    vm->cp = MQO_CP;
    vm->ep = MQO_EP;
    vm->gp = MQO_GP;
    vm->rx = MQO_RX;
}

void mqo_activate_vm( mqo_process process, mqo_vm vm ){
    mqo_load_vm( vm );
    mqo_interp_loop( );
}

void mqo_deactivate_vm( mqo_process process, mqo_vm vm ){
    mqo_save_vm( vm );
}

void mqo_activate_prim( mqo_process process, mqo_list call ){
    MQO_AP = NULL;
    MQO_CP = NULL;
    MQO_EP = NULL;
    MQO_GP = NULL;
    MQO_IP = NULL;

    mqo_chain( call );
    if( MQO_IP ){
        //TEST: This permits a primitive to chain into a procedure that
        //      can pause.
        mqo_vm vm = mqo_make_vm( ); mqo_save_vm( vm );
        process->activate = (mqo_proc_fn) mqo_activate_vm;
        process->deactivate = (mqo_proc_fn) mqo_deactivate_vm;
        process->context = mqo_vf_vm( vm );
    }else{
        mqo_disable_process( process );
    }
}

void mqo_deactivate_prim( mqo_process process, mqo_primitive prim ){
    return;
}

mqo_process mqo_spawn_call( mqo_pair call ){
    mqo_list rest = mqo_list_fv( mqo_cdr( call ) );
    mqo_value func = mqo_reduce_function( mqo_car( call ), rest );
    call = mqo_cons( func, mqo_vf_list( rest ) );
    mqo_process p;

    if( mqo_is_primitive( func ) ){
        p = mqo_make_process( (mqo_proc_fn)mqo_activate_prim, 
                              (mqo_proc_fn)mqo_deactivate_prim,
                              func );
    }else{
        mqo_vm vm = mqo_make_vm( );
        vm->cp = mqo_make_callframe();
        vm->cp->head = call;
        vm->cp->tail = mqo_last_pair( call );
        vm->cp->count = mqo_list_length( call );

        if( mqo_is_closure( func ) ){
            mqo_closure c = mqo_closure_fv( func );
            vm->ep = c->env;
            vm->ip = c->inst;
        }else if( mqo_is_procedure( func ) ){
            vm->ip = mqo_procedure_fv( func )->inst;
        }else{
            assert(0);
            mqo_errf( mqo_es_vm, "sx", "only functions can be spawned", func );
        }
        
        p = mqo_make_process( (mqo_proc_fn)mqo_activate_vm, 
                              (mqo_proc_fn)mqo_deactivate_vm, 
                              mqo_vf_vm( vm ) );
    };
   
    mqo_enable_process( p );

    return p;
}

mqo_process mqo_spawn_thunk( mqo_value thunk ){
    mqo_spawn_call( mqo_cons( thunk, mqo_vf_null( ) ) );
}

void mqo_trace_process( mqo_process process ){
    mqo_grey_obj( (mqo_object) process->prev );
    mqo_grey_obj( (mqo_object) process->next );
    mqo_grey_obj( (mqo_object) process->context );
    mqo_grey_obj( (mqo_object) process->monitoring );
    mqo_grey_obj( (mqo_object) process->input );
    mqo_grey_obj( (mqo_object) process->output );
}

MQO_C_TYPE( process );

void mqo_trace_vm( mqo_vm vm ){
    if( vm->ip )mqo_grey_obj( (mqo_object) vm->ip->proc );
    mqo_grey_obj( (mqo_object) vm->ap );
    mqo_grey_obj( (mqo_object) vm->cp );
    mqo_grey_obj( (mqo_object) vm->ep );
    mqo_grey_obj( (mqo_object) vm->gp );
    mqo_grey_val( vm->rx );
}

MQO_GENERIC_FREE( vm );
MQO_GENERIC_FORMAT( vm );
MQO_GENERIC_COMPARE( vm );
MQO_C_TYPE( vm );

MQO_BEGIN_PRIM( "spawn", spawn )
    REQ_FUNCTION_ARG( func )
    NO_REST_ARGS( );
     
    mqo_process p = mqo_spawn_thunk( func );

    mqo_set_process_output( p, mqo_process_output( mqo_active_process ) );
    mqo_set_process_input( p, mqo_process_input( mqo_active_process ) );

    PROCESS_RESULT( p );
MQO_END_PRIM( spawn )

MQO_BEGIN_PRIM( "active-process", active_process )
    NO_REST_ARGS( );
    
    RESULT( mqo_vf_process( mqo_active_process ) );
MQO_END_PRIM( active_process )

MQO_BEGIN_PRIM( "halt", halt )
    NO_REST_ARGS( );
    mqo_disable_process( mqo_active_process );
    mqo_proc_loop( );
    NO_RESULT( );
MQO_END_PRIM( halt )

MQO_BEGIN_PRIM( "pause", pause )
    NO_REST_ARGS( );
    MQO_CP = MQO_CP->cp;
    MQO_RX = mqo_vf_null( );
    mqo_process p = mqo_active_process;
    mqo_disable_process( p );
    mqo_enable_process( p );
    mqo_proc_loop( );
MQO_END_PRIM( pause )

void mqo_init_process_subsystem( ){
    MQO_I_TYPE( process );
    MQO_I_TYPE( vm );

    MQO_BIND_PRIM( spawn );
    MQO_BIND_PRIM( pause );
    MQO_BIND_PRIM( halt );
    MQO_BIND_PRIM( active_process );
}
