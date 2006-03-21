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
#include <string.h>

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
    // printf( "%4i", si );
    mqo_write( "[" );
    for( int i = 0; i < si; i ++ ){
        mqo_value v = mqo_vector_get( sv, i );
        mqo_space( );
        if( mqo_is_instruction( v ) ){
            mqo_write( "ip:" );
            mqo_write_address( v.data );
        }else if( mqo_is_program( v ) ){
            mqo_write( "pp:" );
            mqo_write_address( v.data );
        }else{
            mqo_word ct = 3; mqo_show( v, &ct );
        }
    }
    mqo_write( " ]" );
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
                if( MQO_PP == NULL )return;
                MQO_PP->status = mqo_ps_running;
                while( MQO_IP ){
                    if( mqo_trace_vm ){
                        // mqo_writeint( MQO_RI );
                        // mqo_write( " : " );
                        mqo_dump_stack( MQO_SV, MQO_SI );
                        mqo_write( " -- " );
                        mqo_word ct = 3; mqo_show_instruction( MQO_IP, &ct );
                        mqo_write( "\n" );
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
        mqo_write( "JUMP" );
        mqo_dump_stack( MQO_RV, MQO_RI );
        mqo_write( " -- " );
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
        mqo_errf( mqo_es_vm, "sx", "could not execute value", fn );
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
        mqo_write( "RETN" );
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
        row->prim = mqo_make_prim( mqo_symbol_fs( row->name ), row->fn );
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
//TODO: mqo_halt should call mqo_stop_reading.
void mqo_resume( mqo_process process, mqo_value value ){
    if( process->status != mqo_ps_suspended )return;
    //TODO: Signal an error.

    if( process->reading )mqo_stop_reading( (mqo_descr)process->reading );
    
    process->status = mqo_ps_paused;
    mqo_vector_put( process->state->sv,
                    process->state->si++,
                    value );
    mqo_resched_process( process );
}
void mqo_show_closure( mqo_closure c, mqo_word* ct ){
    if( ! c )return mqo_show_unknown( mqo_closure_type, 0 );

    mqo_write( "[closure " );
    if( c->name ){
        mqo_writesym( c->name );
        mqo_write( "/" );
    };
    mqo_write_address( (mqo_integer)c );
    mqo_write( "]" );
}
void mqo_show_prim( mqo_prim p, mqo_word* ct ){
    if( ! p )mqo_show_unknown( mqo_prim_type, 0 );

    mqo_write( "[prim " );
    mqo_writesym( p->name );
    mqo_write( "]" );
}
void mqo_show_process( mqo_process p, mqo_word* ct ){
    mqo_writech( '[' );
    mqo_writesym( p->status );
    mqo_write( " process " );
    mqo_writeint( (mqo_integer)p );
    mqo_writech( ']' );
}
mqo_closure mqo_make_closure( mqo_program cp, mqo_instruction ip, mqo_pair ep ){
    mqo_closure c = MQO_ALLOC( mqo_closure, 0 );
    
    c->cp = cp;
    c->ip = ip;
    c->ep = ep;

    return c;
}
mqo_vmstate mqo_make_vmstate( ){
    mqo_vmstate e = MQO_ALLOC( mqo_vmstate, 0 );

    return e;
}
mqo_prim mqo_make_prim( mqo_symbol name, mqo_prim_fn fn ){
    mqo_prim p = MQO_ALLOC( mqo_prim, 0 );
    p->name = name;
    p->fn = fn;
    return p;
}
mqo_process mqo_make_process( ){
    mqo_process p = MQO_ALLOC( mqo_process, 0 );
    mqo_vmstate s = mqo_make_vmstate( );
    p->status = mqo_ps_suspended;
    p->state = s;
    p->reading = NULL;
    s->rv = mqo_make_vector( MQO_STACK_SZ );
    s->sv = mqo_make_vector( MQO_STACK_SZ );
    return p;
}
mqo_multimethod mqo_make_multimethod( 
   mqo_value signature, mqo_value func, mqo_value next
){
    mqo_multimethod mt = MQO_ALLOC( mqo_multimethod, 0 );
    mt->signature = signature;
    mt->func = func;
    mt->next = next;
    return mt;
}
