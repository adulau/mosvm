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
#include "mosvm/prim.h"
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

mqo_boolean mqo_trace_vm = 0;
mqo_symbol mqo_es_os = NULL;
mqo_symbol mqo_es_vm = NULL;
mqo_symbol mqo_es_args = NULL;
mqo_symbol mqo_ps_suspended = NULL;
mqo_symbol mqo_ps_running = NULL;
mqo_symbol mqo_ps_halted = NULL;
mqo_symbol mqo_ps_paused = NULL;
mqo_process mqo_first_process = NULL;
mqo_process mqo_last_process = NULL;

struct mqo_op_row mqo_op_table[] = {
    {"stop", mqo_prim_stop_op, 0, 0, 0, 0, NULL}, //0
    {"ldc",  mqo_prim_ldc_op,  0, 1, 0, 0, NULL}, //1
    {"ldg",  mqo_prim_ldg_op,  1, 0, 0, 0, NULL}, //2
    {"ldb",  mqo_prim_ldb_op,  0, 0, 1, 1, NULL}, //3
    {"ldf",  mqo_prim_ldf_op,  0, 0, 1, 0, NULL}, //4
    {"stg",  mqo_prim_stg_op,  1, 0, 0, 0, NULL}, //5
    {"stb",  mqo_prim_stb_op,  0, 0, 1, 1, NULL}, //6
    {"jmp",  mqo_prim_jmp_op,  0, 0, 1, 0, NULL}, //7
    {"jf",   mqo_prim_jf_op,   0, 0, 1, 0, NULL}, //8
    {"call", mqo_prim_call_op, 0, 0, 0, 0, NULL}, //9
    {"tail", mqo_prim_tail_op, 0, 0, 0, 0, NULL}, //10
    {"retn", mqo_prim_retn_op, 0, 0, 0, 0, NULL}, //11
    {"usen", mqo_prim_usen_op, 0, 0, 1, 1, NULL}, //12
    {"usea", mqo_prim_usea_op, 0, 0, 1, 1, NULL}, //13
    {"ldu",  mqo_prim_ldu_op,  0, 0, 0, 0, NULL}, //14
    {"drop", mqo_prim_drop_op, 0, 0, 0, 0, NULL}, //15
    {"gar",  mqo_prim_gar_op,  0, 0, 1, 0, NULL}, //16
    {"rag",  mqo_prim_rag_op,  0, 0, 0, 0, NULL}, //17
    {"jt",   mqo_prim_jt_op,   0, 0, 1, 0, NULL}, //18
    {"copy", mqo_prim_copy_op, 0, 0, 0, 0, NULL}, //19
    {NULL,   NULL,             0, 0, 0, 0, NULL}  //end
};

mqo_vector  MQO_SV; // The vector containing the current stack.
mqo_integer MQO_SI; // The offset of the top of the current stack in SV.

mqo_vector  MQO_RV; // The vector containing continuations.
mqo_integer MQO_RI; // The offset of the last continuation in AV.

mqo_pair    MQO_EP; // The environment pair chain.
mqo_pair    MQO_GP; // The guard pair chain.

mqo_program MQO_CP; // The current program.
mqo_instruction MQO_IP; // Next instruction.

mqo_process MQO_PP; // The current process -- whose state is not current.

jmp_buf*    MQO_XP;

void mqo_dump_stack( mqo_vector sv, mqo_integer si ){
    printf( "%4i", si );
    printf( "[" );
    for( int i = 0; i < si; i ++ ){
        mqo_value v = mqo_vector_get( sv, i );
        mqo_space( );
        if( mqo_is_instruction( v ) ){
            mqo_show_cstring( "ip:" );
            printf( "%x", v.data );
        }else if( mqo_is_program( v ) ){
            mqo_show_cstring( "pp:" );
            printf( "%x", v.data );
        }else{
            mqo_show( v, 3 );
        }
    }
    printf( " ]" );
}
void mqo_continue( ){
    if(! MQO_XP ){
        jmp_buf xit;

        MQO_XP = &xit;
        int flag = setjmp( xit );
        for(;;){
            switch( flag ){
            case 0: // setjmp always returns 0.
            case MQO_NEXT_INSTR:
                MQO_PP->status = mqo_ps_running;
                while( MQO_IP ){
                    if( mqo_trace_vm ){
                        mqo_show_integer( MQO_RI );
                        mqo_show_cstring( " : " );
                        mqo_dump_stack( MQO_SV, MQO_SI );
                        mqo_show_cstring( " -- " );
                        mqo_show_instruction( MQO_IP, 3 );
                        mqo_show_cstring( "\n" );
                    };
                    MQO_IP->prim->fn();
                }
                MQO_PP->status = mqo_ps_halted;
                mqo_unsched_process( MQO_PP );
            case MQO_NEXT_PROC:
                if( MQO_PP->next ){
                    mqo_use_process( MQO_PP->next );
                }else{
                    mqo_use_process( NULL );
                    mqo_dispatch_monitors( );
                    if( mqo_first_process ){
                        mqo_use_process( mqo_first_process );
                    }else{
                        MQO_XP = NULL; 
                        return;
                    }
                }
                flag = 0;
            }
        }
    }else{
        MQO_CONTINUE( );
    }
}

void mqo_sched_process( mqo_process process ){
    if( mqo_first_process ){
        process->prev = mqo_last_process;
        mqo_last_process->next = process;
        mqo_last_process = process;
    }else{
        mqo_first_process = mqo_last_process = process;
        mqo_use_process( process );
    }
}

void mqo_resched_process( mqo_process process ){
    mqo_unsched_process( process );
    mqo_sched_process( process );
}

void mqo_unsched_process( mqo_process process ){
    if( process->prev ){
        process->prev->next = process->next;
    }else if( mqo_first_process == process ){
        mqo_first_process = process->next;
    }

    if( process->next ){
        process->next->prev = process->prev;
    }else if( mqo_last_process == process ){
        mqo_last_process = process->prev;
    }

    process->prev = process->next = NULL;
}

void mqo_exec( mqo_value function ){
    mqo_push_int_ds( 0 ); // Execute treats the function as a thunk.
    mqo_call( function );
    mqo_continue( );
}

mqo_program mqo_tadpole = NULL;

mqo_process mqo_spawn( mqo_value function ){
    // The tadpole program will automatically tail into the supplied
    // function. This elaborate ruse is necessary in case the function
    // was a primitive.

    mqo_process process = mqo_make_process( );
    process->state->sv->data[ 0 ] = mqo_vf_integer( 0 );
    process->state->sv->data[ 1 ] = function;
    process->state->si = 2;
    process->state->ri = 0;
    process->state->cp = mqo_tadpole;
    process->state->ip = mqo_tadpole->inst;
    process->status = mqo_ps_paused;

    mqo_sched_process( process );

    return process;
}

mqo_value mqo_execute( mqo_value function ){
    mqo_process p = mqo_spawn( function );
    while( mqo_first_process )mqo_continue( );

    return( p->state->si > 0 ? p->state->sv->data[ p->state->si - 1 ] 
                             : mqo_vf_false( ) );
}

mqo_value mqo_resolve_method( mqo_multimethod mt ){
    mqo_integer ct = mqo_integer_fv( mqo_vector_get( MQO_SV, MQO_SI - 1 ) );
    mqo_value* vp = mqo_vector_ref( MQO_SV, MQO_SI - ct - 1 );
    mqo_value sig;
    mqo_integer ix;
again:
    sig = mt->signature;
    ix = 0;
    while(( ix < ct )&&( ! mqo_is_empty( sig ) )){
        if( mqo_is_true( sig ) ){
            return mt->func;
        }else if( mqo_is_pair( sig ) ){
            mqo_value vt = mqo_car( mqo_pair_fv( sig ) );

            if((
                mqo_is_true( vt ) 
            )||(
                mqo_is_type( vt ) && mqo_isa( vp[ix], mqo_type_fv( vt ) ) 
            )){
                sig = mqo_cdr( mqo_pair_fv( sig ) ); 
                ix ++;
            }else{
                if( mqo_is_multimethod( mt->next ) ){
                    mt = mqo_multimethod_fv( mt->next );
                    goto again;
                }else{
                    return mt->next;
                }
            }
        }
    };
    if(( ix < ct )||( ! mqo_is_empty( sig ) )){
        return mt->next;
    }else{
        return mt->func;
    }
}
void mqo_jump( mqo_value fn ){
    mqo_closure c;
    mqo_program p;

again:
/*    if( mqo_trace_vm ){
        mqo_show_cstring( "JUMP" );
        mqo_dump_stack( MQO_RV, MQO_RI );
        mqo_show_cstring( " -- " );
        mqo_show( fn, 3 );
        mqo_newline();
    };
*/
/*
    for( int i = 0; i < (MQO_RI / 5); i++ ){
        putchar( '.' );
    }; mqo_show( fn, 4 ); mqo_newline();

*/
    mqo_push_rs( fn );

    if( mqo_is_prim( fn ) ){
        mqo_push_int_rs( mqo_peek_int_ds() );
        mqo_prim_fv(fn)->fn();
    }else if( mqo_is_closure( fn ) ){
        c = mqo_closure_fv( fn );
        MQO_CP = c->cp;
        MQO_IP = c->ip;
        MQO_EP = c->ep;
    }else if( mqo_is_program( fn ) ){
        p = mqo_program_fv( fn );
        MQO_CP = p; 
        MQO_IP = p->inst;
        MQO_EP = NULL;
    }else if( mqo_is_multimethod( fn ) ){
        mqo_pop_rs();
        fn = mqo_resolve_method( mqo_multimethod_fv( fn ) );
        goto again;
    }else{
		mqo_pop_rs();
		mqo_pop_rs();
		mqo_pop_rs();
		mqo_pop_rs();
        mqo_errf( mqo_es_vm, "sx", "mosvm does not know how to execute", fn );
    };
}

void mqo_tail_call( mqo_value fn ){
    // Should not be used from prims other than the tail op or apply.
    
    mqo_drop_rs( 2 );
    mqo_jump( fn );     
}

void mqo_call( mqo_value fn ){
    mqo_push_rs( mqo_vf_program( MQO_CP ) );
    mqo_push_rs( mqo_vf_instruction( MQO_IP ) );
    mqo_push_pair_rs( MQO_EP );
    mqo_jump( fn );
}

void mqo_return( ){
    /*if( mqo_trace_vm ){
        mqo_show_cstring( "RETN" );
        mqo_dump_stack( MQO_RV, MQO_RI );
        mqo_newline();
    };
    */
    if( MQO_RI ){
        mqo_pop_rs();
        mqo_pop_rs();
        MQO_EP = mqo_pop_pair_rs(); 
        MQO_IP = mqo_instruction_fv( mqo_pop_rs() );
        MQO_CP = mqo_program_fv( mqo_pop_rs() );
    }else{
        MQO_IP = NULL;
    }
}

void mqo_err( mqo_symbol key, mqo_pair info ){
    mqo_error err = mqo_make_error( key, info );

    if( MQO_GP ){
        mqo_guard g = mqo_guard_fv( mqo_car( MQO_GP ) );

        MQO_GP = mqo_pair_fv( mqo_cdr( MQO_GP ) );
        MQO_SI = g->si;
        MQO_RI = g->ri;
        MQO_CP = g->cp;
        MQO_IP = g->ip;
        MQO_EP = g->ep;

        mqo_push_ds( mqo_vf_error( err ) );
        mqo_push_int_ds( 1 );

        mqo_call( g->fn );
        
        MQO_CONTINUE( );
    }else{
        mqo_il_traceback( err );
        MQO_IP = NULL;
        MQO_EP = NULL;
        MQO_SI = MQO_RI = 0;
        // We will rely on mqo_execute to identify an empty data stack
        // as the result of an unhandled error condition.

        MQO_HALT( );
    }
}

void mqo_il_traceback( mqo_error error ){
    mqo_vector  rv = error->state->rv;
    mqo_vector  sv = error->state->sv;
    mqo_integer ri = error->state->ri;
    mqo_integer si = error->state->si;
    mqo_value*  af = NULL;
    mqo_integer ai = 0, ct = 0;
    mqo_pair ep = error->state->ep;

    mqo_value fn, x;
    
    int tc = 0;
    
    void load_stack_frame( ){
        // A stack frame is always the last frame, since they are
        // only used by primitives, and primitives NEVER call, they only
        // jump.
        //TODO: Signal an error if si < ct + 2;
        si = si - ct - 1;
        af = mqo_vector_ref( sv, si );
    }
    void load_env_frame( ){
        //TODO: Signal an error if ct < ep->length
        //TODO: Signal an error if (not? (vector? (car ep)))
        if( ct ){
            af = mqo_vector_ref( mqo_vector_fv( mqo_car( ep ) ), 0 );
        }else{
            af = NULL;
        }
    }
    void show_call( ){
        mqo_show_cstring( "(" );

        if( mqo_is_closure( fn ) ){
            mqo_closure c = mqo_closure_fv( fn );
            
            if( c->name ){
                mqo_show_symbol( c->name );
            }else{
                mqo_show_closure( c );
            }
            
            load_env_frame( );
        }else if( mqo_is_program( fn ) ){
            mqo_show_cstring( "<program>" );
            load_env_frame( );
        }else if( mqo_is_prim( fn ) ){
            mqo_show_string( mqo_prim_fv( fn )->name );
            if( tc ){
                //TODO: Signal an error if this is not the first show_call.
                mqo_show_cstring( "...)" );
                return;
            }else{
                load_stack_frame( );
            }
        }else{
            mqo_show( fn, 5 );
        };
    
        for( ai = 0; ai < ct; ai ++ ){
            mqo_space();
            if( ai == 5 ){ 
                mqo_show_cstring ( "..." ); 
                break; 
            }
            mqo_show( af[ ai ], 5 );
        }
        
        mqo_show_cstring( ")" );
    }   
    
    // Display the Key and Info
    mqo_newline( );
    mqo_show_cstring( "Error: " );
    mqo_show_symbol( error->key );
    if( error->info ){
    mqo_show_cstring( ":" );
        MQO_FOREACH( error->info, pair ){
            mqo_space( );
            mqo_show( mqo_car( pair ), 16 );
        }
    }
    mqo_newline( );

    // Display the stacks.
    mqo_show_cstring( "DS: " );
    mqo_dump_stack( sv, si );
    mqo_show_cstring( "\nRS: " );
    mqo_dump_stack( rv, ri );
    mqo_show_cstring( "\n" );

    // Display the Traceback
    mqo_show_cstring( "Trace: " );

    while( ri > 1 ){ //Note, there's always one base RI from the executing
                     //program.
        if( tc > 0 ) mqo_show_cstring( "       " );
      
        if( ri < 5 ){
            //TODO: Signal an error.
            return;
        }

        x = mqo_vector_get( rv, --ri );
        if( ! mqo_is_integer( x ) ){
            //TODO: Signal an error.
            return;
        }
        ct = mqo_integer_fv( x );
        fn = mqo_vector_get( rv, --ri );
        
        show_call( );
        mqo_newline( );
        
        x = mqo_vector_get( rv,  --ri );
        if( ! mqo_is_pair( x ) ){
            //TODO: Signal an error.
            return;
        }
        ep = mqo_pair_fv( x );

        ri -= 2;
        tc++;
    }
}

mqo_pair mqo_rest( mqo_integer ct, mqo_integer dp ){
    mqo_pair pr = NULL;
    for( mqo_integer ai = 0; ai < ct; ai ++ ){
        pr = mqo_cons( 
            mqo_vector_get( MQO_SV, MQO_SI - ai - 1 - dp), 
            mqo_vf_pair( pr ) 
        );
    }
    return pr;
}

void mqo_errf( mqo_symbol key, const char* fmt, ... ){
    va_list ap;
    mqo_pair head = NULL;
    mqo_pair tail = NULL;
    mqo_pair item = NULL;
    
    const char* ptr = fmt;
    va_start( ap, fmt );
    for(;;){
        mqo_value value;

        switch( *(ptr++) ){
        case 'x':
            value = va_arg( ap, mqo_value );
            break;
        case 's': 
            value = mqo_vf_string( 
                mqo_string_fs( va_arg( ap, const char* ) ) );
            break;
        case 'S': 
            value = mqo_vf_string( va_arg( ap, mqo_string ) );
            break;
        case 'i': 
            value = mqo_vf_integer( va_arg( ap, mqo_integer ) );
            break;
        case 0:
            goto done;
        default:
            va_end( ap );
            mqo_errf( mqo_es_vm, "ss", 
                "mqo_errf cannot process format string", fmt );
        }

        item = mqo_cons( value, mqo_vf_empty( ) );
        if( tail ){ 
            mqo_set_cdr( tail, mqo_vf_pair( item ) );
        }else{ 
            head = item;
        };
        tail = item;
    }
done:
    va_end( ap );
    mqo_err( key, head );
}
void mqo_init_exec_subsystem( ){
    mqo_es_os = mqo_symbol_fs( "os" );
    mqo_es_vm = mqo_symbol_fs( "vm" );
    mqo_es_args = mqo_symbol_fs( "bad-args" );
    mqo_ps_suspended = mqo_symbol_fs( "suspended" );
    mqo_ps_running = mqo_symbol_fs( "running" );
    mqo_ps_halted = mqo_symbol_fs( "halted" );
    mqo_ps_paused = mqo_symbol_fs( "paused" );
    mqo_integer ct = 0;

    for(;;){
        struct mqo_op_row* row = mqo_op_table + ( ct ++ );
        if( row->fn == NULL )break;
        row->prim = mqo_make_prim( row->name, row->fn );
    }

    mqo_tadpole = mqo_make_program( 2 );
    mqo_tadpole->inst[0].code = 9; //CALL
    mqo_tadpole->inst[0].prim = mqo_op_table[ 9 ].prim;
    mqo_tadpole->inst[1].code = 0; //STOP
    mqo_tadpole->inst[1].prim = mqo_op_table[ 0 ].prim;
}
void mqo_use_process( mqo_process p ){
    mqo_vmstate s;

    if( MQO_PP ){
        s = MQO_PP->state;
        s->cp = MQO_CP;
        s->ip = MQO_IP;
        s->sv = MQO_SV;
        s->si = MQO_SI;
        s->rv = MQO_RV;
        s->ri = MQO_RI;
        s->ep = MQO_EP;
        s->gp = MQO_GP;
    };
    
    MQO_PP = p;

    if( p ){
        s = p->state;

        MQO_CP = s->cp;
        MQO_IP = s->ip;
        MQO_SV = s->sv;
        MQO_SI = s->si;
        MQO_RV = s->rv;
        MQO_RI = s->ri;
        MQO_EP = s->ep;
        MQO_GP = s->gp;
    };
}
void mqo_resume( mqo_process process, mqo_value value ){
    printf( "Resumed process %x status was: ", process );
    mqo_show_symbol( process->status );
    mqo_newline( );
    printf( "Current process is %x\n", MQO_PP );
    if( process->status == mqo_ps_suspended ){
        process->status = mqo_ps_paused;
        mqo_vector_put( process->state->sv,
                        process->state->si++,
                        value );
        mqo_resched_process( process );
    }
    printf( "First process is now: %x\n", mqo_first_process );
}
void mqo_report_os_error( ){
    mqo_errf( mqo_es_os, "s", strerror( errno ) );
}
int mqo_os_error( int code ){
    if( code == -1 ){
        mqo_report_os_error( );
    }else{
        return code;
    }
}
