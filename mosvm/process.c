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

mqo_process mqo_first_enabled = NULL;
mqo_process mqo_last_enabled = NULL;
mqo_process mqo_active_process = NULL;

void mqo_activate_vm( mqo_process process, mqo_vm vm );
void mqo_activate_netmon( mqo_process process, mqo_object );

MQO_GENERIC_SHOW( process );
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
    process->input = mqo_vf_null( );
    process->output = mqo_vf_null( );
    return process;
}

mqo_vm mqo_make_vm( ){
    mqo_vm vm = MQO_OBJALLOC( vm );
    vm->ip = NULL;
    vm->ap = NULL;
    vm->cp = NULL;
    vm->ep = NULL;
    vm->gp = NULL;
    vm->rx = 0;
    return vm;
}

void mqo_enable_process( mqo_process process ){
    if( process->enabled )return; 

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

void mqo_activate_prim( mqo_process process, mqo_primitive prim ){
    MQO_AP = NULL;
    MQO_CP = NULL;
    MQO_EP = NULL;
    MQO_GP = NULL;
    MQO_IP = NULL;

    mqo_chain( mqo_cons( mqo_vf_primitive( prim ), mqo_vf_null() ) );
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

mqo_process mqo_spawn_func( mqo_value func ){
    mqo_process process;
    func = mqo_reduce_function( func, NULL );
    
    if( mqo_is_primitive( func ) ){
        process = mqo_make_process( (mqo_proc_fn)mqo_activate_prim, 
                                    (mqo_proc_fn)mqo_deactivate_prim,
                                    func );
    }else{
        mqo_vm vm = mqo_make_vm( );

        vm->cp = mqo_make_callframe();
        vm->cp->head = vm->cp->tail = mqo_cons( func, mqo_vf_null( ) );
        vm->cp->count = 1;

        if( mqo_is_closure( func ) ){
            mqo_closure c = mqo_closure_fv( func );
            vm->ep = c->env;
            vm->ip = c->inst;
        }else if( mqo_is_procedure( func ) ){
            vm->ip = mqo_procedure_fv( func )->inst;
        }else{
            mqo_errf( mqo_es_vm, "sx", "only functions can be spawned", func );
        }

        process = mqo_make_process( (mqo_proc_fn)mqo_activate_vm, 
                                    (mqo_proc_fn)mqo_deactivate_vm, 
                                    mqo_vf_vm( vm ) );
    }

    mqo_enable_process( process );

    return process; 
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
MQO_GENERIC_SHOW( vm );
MQO_GENERIC_COMPARE( vm );
MQO_C_TYPE( vm );

MQO_BEGIN_PRIM( "spawn", spawn )
    REQ_FUNCTION_ARG( func )
    NO_REST_ARGS( );
    
    PROCESS_RESULT( mqo_spawn_func( func ) );
MQO_END_PRIM( spawn )

MQO_BEGIN_PRIM( "active-process", active_process )
    NO_REST_ARGS( );
    
    RESULT( mqo_vf_process( mqo_active_process ) );
MQO_END_PRIM( active_process )

MQO_BEGIN_PRIM( "process-input", process_input )
    OPT_PROCESS_ARG( process )
    NO_REST_ARGS( );
    if( ! has_process ) process = mqo_active_process;
    RESULT( process->input );
MQO_END_PRIM( process_input )

MQO_BEGIN_PRIM( "set-process-input!", set_process_input )
    REQ_ANY_ARG( input );
    OPT_ANY_ARG( process );
    NO_REST_ARGS( );

    if( has_process ){
        mqo_req_process( input )->input = process;
    }else{
        mqo_active_process->input = input;
    }
    
    NO_RESULT( );
MQO_END_PRIM( set_process_input )

MQO_BEGIN_PRIM( "process-output", process_output )
    OPT_PROCESS_ARG( process )
    NO_REST_ARGS( );
    if( ! has_process ) process = mqo_active_process;
    RESULT( process->output );
MQO_END_PRIM( process_output )

MQO_BEGIN_PRIM( "set-process-output!", set_process_output )
    REQ_ANY_ARG( output );
    OPT_ANY_ARG( process );
    NO_REST_ARGS( );

    if( has_process ){
        mqo_req_process( output )->output = process;
    }else{
        mqo_active_process->output = output;
    }
    
    NO_RESULT( );
MQO_END_PRIM( set_process_output )

void mqo_init_process_subsystem( ){
    MQO_I_TYPE( process );
    MQO_I_TYPE( vm );

    MQO_BIND_PRIM( spawn );
    MQO_BIND_PRIM( active_process );
    MQO_BIND_PRIM( process_input );
    MQO_BIND_PRIM( set_process_output );
    MQO_BIND_PRIM( process_output );
    MQO_BIND_PRIM( set_process_output );
}
