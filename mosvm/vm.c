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

void mqo_trace_step( );
mqo_primitive mqo_instr_table[ 32 ];

mqo_byte mqo_max_opcode = 0;

jmp_buf* mqo_interp_xp;
jmp_buf* mqo_proc_xp;

mqo_callframe   MQO_AP;
mqo_callframe   MQO_CP;
mqo_pair        MQO_EP;
mqo_pair        MQO_GP;
mqo_instruction MQO_IP;
mqo_value       MQO_RX;

mqo_integer mqo_trace_flag = 0;

mqo_callframe mqo_make_callframe( ){
    mqo_callframe frame = MQO_OBJALLOC( callframe );
    return frame;
}
void mqo_trace_registers( ){
    mqo_grey_obj( (mqo_object) MQO_AP );
    mqo_grey_obj( (mqo_object) MQO_CP );
    mqo_grey_obj( (mqo_object) MQO_EP );
    mqo_grey_obj( (mqo_object) MQO_GP );
    if( MQO_IP ) mqo_grey_obj( (mqo_object) MQO_IP->proc );
    mqo_grey_val( MQO_RX );
}
void mqo_bind_op( const char* name, mqo_prim_fn impl, 
                  mqo_boolean a, mqo_boolean b ){
    mqo_primitive prim = mqo_make_primitive( name, impl );
    prim->code = mqo_max_opcode;
    prim->a = a;
    prim->b = b;
    mqo_root_obj( (mqo_object) prim );
    mqo_instr_table[ mqo_max_opcode ++ ] = prim ;
}
mqo_primitive mqo_lookup_op( mqo_symbol name ){
    int i; 
    for( i = 0; i < mqo_max_opcode; i ++ ){
        if( mqo_instr_table[i]->name == name )return mqo_instr_table[i];
    }
    return NULL;
}
void mqo_interp_loop( ){
    // Only one interpreter loop is permitted in the current call stack; we
    // long jump back to it.
    if( mqo_interp_xp )return longjmp( *mqo_interp_xp, 102 );

    // An interp loop is only permitted subordinate to a process loop; if it
    // is absent, we will kick it off.
    if( ! mqo_proc_xp )return mqo_proc_loop( );

    jmp_buf exit; 
    mqo_interp_xp = &exit;
    setjmp( exit );
    
    while( MQO_IP ){
        if( mqo_trace_flag )mqo_trace_step();
        MQO_IP->prim->impl( );
        mqo_collect_window( );
    };
    
    mqo_disable_process( mqo_active_process );
    mqo_interp_xp = NULL;
}

#define MQO_AX ( MQO_IP->a )
#define MQO_BX ( MQO_IP->b )

void mqo_add_call_arg( mqo_value x ){
    mqo_pair p = mqo_cons( x, mqo_vf_null() );

    if(  MQO_AP->count++ ){
        mqo_set_cdr( MQO_AP->tail, mqo_vf_pair( p ) );
    }else{
        MQO_AP->head = p;
    }

    MQO_AP->tail = p;
}

void mqo_next_instr( ){ MQO_IP ++; }

void mqo_instr_arg( ){
  // (call-add-item! ap rx)
  // (set! ip (next-instr ip)) 
  
    mqo_add_call_arg( MQO_RX );
    mqo_next_instr( );
}
void mqo_instr_scat( ){
  // (for-each (lambda (rx) (call-add-item! ap rx))
  //           rx)
  // (set! ip (next-instr ip)) 
    
    mqo_pair p;
    for( p = mqo_req_list( MQO_RX ); p; p = mqo_req_list( mqo_cdr( p ) ) ){
        mqo_add_call_arg( mqo_car( p ) );
    }
    mqo_next_instr( );
}
void mqo_jump( ){
    if( ! MQO_CP->head ){
        mqo_errf( mqo_es_vm, "s", "cannot evaluate an empty application" );
    }

    mqo_value fn = mqo_car( MQO_CP->head );
    mqo_pair  args = mqo_list_fv( mqo_cdr( MQO_CP->head ) );
    mqo_integer ct = MQO_CP->count;

    fn = mqo_reduce_function( fn, args );
    
    if( mqo_is_closure( fn ) ){
        mqo_closure clos = mqo_closure_fv( fn );

        MQO_EP = mqo_clos_env( clos );
        MQO_IP = mqo_clos_inst( clos );
    }else if( mqo_is_primitive( fn ) ){
        mqo_arg_ptr = args;
        mqo_arg_ct = ct;
        MQO_AP = MQO_CP->ap;
        MQO_EP = MQO_CP->ep;
        MQO_IP = MQO_CP->ip;
        mqo_primitive_fv( fn )->impl();
        MQO_CP = MQO_CP->cp;
    }else if( mqo_is_procedure( fn ) ){
        MQO_EP = NULL;
        MQO_IP = mqo_procedure_fv( fn )->inst;
    }else{
        mqo_errf( mqo_es_vm, "sx", "cannot call non-function", fn );
    }
}
void mqo_instr_call( ){
    // Error if call frame is empty
    // (define fn   (call-fn ap))
    // (define args (call-args ap))

    // (if (is-closure? fn)
    //   (begin (set-call-cp! ap cp)
    //          (set-call-ep! ap ep)
    //          (set-call-ip! ap (next-instr ip))
    //          (set! cp ap)
    //          (set! ep (closure-env fn))
    //          (set! ip (proc-instr (closure-proc fn))))
    //   (apply (prim-impl fn) args))

    MQO_AP->cp = MQO_CP;
    MQO_AP->ep = MQO_EP;
    MQO_AP->ip = MQO_IP+1;
    MQO_CP = MQO_AP;
 
    mqo_jump( );
}
void mqo_instr_tail( ){
    // (define fn   (call-fn ap))
    // (define args (call-args ap))

    // (if (is-closure? fn) 
    //   (begin (set-call-data! cp (call-data ap)) 
    //          (set! ep (closure-env fn)) 
    //          (set! ip (proc-instr (closure-proc fn)))) 
    //   (apply (prim-impl fn) args)) 
     
    MQO_CP->head = MQO_AP->head;
    MQO_CP->tail = MQO_AP->tail;
    MQO_CP->count = MQO_AP->count;

    mqo_jump( );
}
void mqo_instr_clos( ){
    // (set! rx (make-closure ep ip))
    // (set! ip (instr-ax ip))
    // (set! ip (next-instr ip))

    MQO_RX = mqo_vf_closure( mqo_make_closure( 
        MQO_AX,
        MQO_IP+1,
        MQO_EP
    ) );

    MQO_IP = MQO_IP->proc->inst + mqo_imm_fv( MQO_BX );
}
void mqo_instr_gar( ){
    // (set! gp (cons (make-guard rx cp ap (instr-ax ip))
    //                gp))
    // (set! ip (next-instr ip))

    MQO_GP = mqo_cons( 
        mqo_vf_guard( mqo_make_guard( MQO_RX, MQO_CP, MQO_AP, MQO_EP, 
                                      MQO_IP->proc->inst + 
                                      mqo_imm_fv( MQO_AX ) ) ), 
        mqo_vf_list( MQO_GP ) );

    mqo_next_instr();
}
void mqo_instr_jmp( ){
    // (set! ip ax)

    MQO_IP = MQO_IP->proc->inst + mqo_imm_fv( MQO_AX );
}
//TODO: Add the prog field to instructions
void mqo_instr_jf( ){
    // (if (eq? #f rx)
    //     (set! ip (instr-ax ip))
    //     (set! ip (next-instr ip)))

    if( mqo_is_false( MQO_RX ) ){
        MQO_IP = MQO_IP->proc->inst + mqo_imm_fv( MQO_AX );
    }else{
        mqo_next_instr();
    }
}
void mqo_instr_jt( ){
    // (if (eq? #f rx)
    //     (set! ip (next-instr ip))
    //     (set! ip (instr-ax ip)))

    if( mqo_is_false( MQO_RX ) ){
        mqo_next_instr();
    }else{
        MQO_IP = MQO_IP->proc->inst + mqo_imm_fv( MQO_AX );
    }
}
void mqo_instr_ldb( ){
    // (set! rx (vector-ref (list-ref ep (instr-ax ip))
    //          (instr-bx ip)))
    // (set! ip (next-instr ip))

    MQO_RX = mqo_vector_get( 
        mqo_vector_fv( 
            mqo_car( mqo_list_ref( MQO_EP, mqo_imm_fv( MQO_AX ) ) ) 
        ), 
        mqo_imm_fv( MQO_BX ) 
    );
    
    mqo_next_instr();
}
void mqo_instr_ldc( ){
    // (set! rx (instr-ax ip))
    // (set! ip (next-instr ip))
    MQO_RX = MQO_AX;

    mqo_next_instr();
}
void mqo_instr_ldg( ){
    // (set! rx (get-global (instr-ax ip)))
    // (set! ip (next-instr ip))
    
    mqo_symbol s = mqo_symbol_fv( MQO_AX );
    if( mqo_has_global( s ) ){
        MQO_RX = mqo_get_global( s );
    }else{
        mqo_errf( mqo_es_vm, "sx", "global not bound", s );
    }
    mqo_next_instr();
}
void mqo_instr_newf( ){
    // (set! ap (make-call-frame))
    // (set! ip (next-instr ip))
    mqo_callframe ap = MQO_AP;
    MQO_AP = mqo_make_callframe();
    MQO_AP->ap = ap; 

    mqo_next_instr();
}
void mqo_instr_rag( ){
    // (set! gp (cdr gp))
    // (set! ip (next-instr ip))

    MQO_GP = mqo_list_fv( mqo_cdr( MQO_GP ) );

    mqo_next_instr();
}
void mqo_instr_retn( ){
    // (set! ep (call-ep cp))
    // (set! ip (call-ip cp))
    // (set! cp (call-cp cp))
    if( MQO_CP ){
        MQO_EP = MQO_CP->ep;
        MQO_IP = MQO_CP->ip;
        MQO_AP = MQO_CP->ap;
        MQO_CP = MQO_CP->cp;
    }else{
        MQO_IP = NULL;
        mqo_interp_loop( );
    }
}
void mqo_instr_stb( ){
    // (vector-set! (list-ref ep (instr-ax ip)) 
    //              (instr-bx ip) 
    //              rx) 
    // (set! ip (next-instr ip)) 

    mqo_vector_put( mqo_vector_fv( mqo_car( mqo_list_ref( MQO_EP, 
                                            mqo_imm_fv( MQO_AX ) ) ) ),
                    mqo_imm_fv( MQO_BX ),
                    MQO_RX );
    mqo_next_instr();
}
void mqo_instr_stg( ){
    // (set-global (instr-ax ip) rx)
    // (set! ip (next-instr ip)) 
    mqo_set_global( mqo_symbol_fv( MQO_AX ), MQO_RX );
    mqo_next_instr();
}
void mqo_instr_usea( ){
    // (define max (instr-ax ip)) 
    mqo_word max = mqo_imm_fv( MQO_AX );

    if(( MQO_CP->count - 1 ) < max ){
        mqo_errf( mqo_es_vm, "sii", "argument underflow", MQO_CP->count, max );
    }

    // (define env (make-vector (instr-bx ip))) 
    mqo_vector env = mqo_make_vector( mqo_imm_fv( MQO_BX ) );

    // (let loop ((ix 0) 
    //            (args (call-args cp))) 
    //   (cond ((= ix max) (vector-set! env ix args)) 
    //         ((null? args)) ;;; Do nothing. 
    //         (else (vector-set! env ix (car args)) 
    //               (loop (+ ix 1) (cdr args))))) 

    mqo_word ix = 0;

    //TODO: Do we want to bind the function called?
    mqo_pair p = mqo_list_fv( mqo_cdr( MQO_CP->head ) );

    for(;;){
        if( ix == max ){
            mqo_vector_put( env, ix, mqo_vf_list( p ) );
            break;
        }else{
            mqo_vector_put( env, ix, mqo_car( p ) );
            p = mqo_list_fv( mqo_cdr( p ) );
            ix ++;
        }
    }

    // (set! ep (cons env ep)) 
    MQO_EP = mqo_cons( mqo_vf_vector( env ), mqo_vf_list( MQO_EP ) );

    // (set! ip (next-instr ip)) 
    mqo_next_instr( );
}
void mqo_instr_usen( ){
    mqo_word max = mqo_imm_fv( MQO_AX ) + 1;

    if( MQO_CP->count < max ){
        mqo_errf( mqo_es_vm, "sii", "argument underflow", MQO_CP->count, max );
    }else if( MQO_CP->count > max ){
        mqo_errf( mqo_es_vm, "sii", "argument overflow", MQO_CP->count, max );
    };

    // (define env (make-vector (instr-bx ip))) 
    mqo_vector env = mqo_make_vector( mqo_imm_fv( MQO_BX ) );

    // (let loop ((ix 0) 
    //            (args (call-args cp))) 
    //   (if (not (null? args)) 
    //     (vector-set! env ix (car args))) 
    //   (loop (+ ix 1) (cdr args))) 

    mqo_word ix = 0;
    //TODO: Do we want to bind the function called?
    mqo_pair p = mqo_list_fv( mqo_cdr( MQO_CP->head ) );

    while( p ){
        mqo_vector_put( env, ix, mqo_car( p ) );
        p = mqo_list_fv( mqo_cdr( p ) );
        ix ++;
    }

    // (set! ep (cons env ep)) 
    MQO_EP = mqo_cons( mqo_vf_vector( env ), mqo_vf_list( MQO_EP ) );

    // (set! ip (next-instr ip)) 
    mqo_next_instr( );
}

void mqo_trace_callframe( mqo_callframe cf ){
    mqo_grey_obj( (mqo_object) cf->ap );
    mqo_grey_obj( (mqo_object) cf->cp );
    mqo_grey_obj( (mqo_object) cf->ep );
    if( cf->ip ) mqo_grey_obj( (mqo_object) cf->ip->proc );
    mqo_grey_obj( (mqo_object) cf->head );
    mqo_grey_obj( (mqo_object) cf->tail );
}

MQO_GENERIC_FREE( callframe );
MQO_GENERIC_COMPARE( callframe );
MQO_GENERIC_FORMAT( callframe );
MQO_C_TYPE2( callframe, "call-frame" )

mqo_symbol mqo_es_vm;

void mqo_init_vm_subsystem( ){
    MQO_I_TYPE( callframe );

    mqo_es_vm = mqo_symbol_fs( "vm" );
    //TODO: We need to get clever and build this statically.

#define MQO_BIND_OP( on, a, b ) \
    mqo_bind_op( #on, mqo_instr_##on, a, b )

    MQO_BIND_OP( arg,  0, 0); //00
    MQO_BIND_OP( call, 0, 0); //01
    MQO_BIND_OP( clos, 1, 1); //02
    MQO_BIND_OP( gar,  1, 0); //03
    MQO_BIND_OP( jf,   1, 0); //04
    MQO_BIND_OP( jmp,  1, 0); //05
    MQO_BIND_OP( jt,   1, 0); //06
    MQO_BIND_OP( ldb,  1, 1); //07
    MQO_BIND_OP( ldc,  1, 0); //08
    MQO_BIND_OP( ldg,  1, 0); //09 
    MQO_BIND_OP( newf, 0, 0); //0a
    MQO_BIND_OP( rag,  0, 0); //0b
    MQO_BIND_OP( retn, 0, 0); //0c
    MQO_BIND_OP( scat, 0, 0); //0d
    MQO_BIND_OP( stb,  1, 1); //0e
    MQO_BIND_OP( stg,  1, 0); //0f
    MQO_BIND_OP( tail, 0, 0); //10
    MQO_BIND_OP( usea, 1, 1); //11
    MQO_BIND_OP( usen, 1, 1); //12
}
void mqo_trace_ip( mqo_instruction ip ){
    mqo_string s = mqo_make_string( 80 );
    mqo_format_hex( s, ip - ip->proc->inst );
    mqo_format_cs( s, ": " );
    mqo_format_instruction( s, ip );
    mqo_prim_fn p = ip->prim->impl;

    int ap = 0, rx = 0;
    
    if( p == mqo_instr_call ){
        ap = 1;
    }else if( p == mqo_instr_tail ){
        ap = 1;
    }else if(( p == mqo_instr_arg ) ||( p == mqo_instr_scat )) {
        ap = 1; rx = 1;
    }else if( p == mqo_instr_stb ){
        rx = 1;
    }else if( p == mqo_instr_stg ){
        rx = 1;
    }
    
    if( ap ){
        mqo_format_cs( s, " -- " );
        mqo_format_pair( s, MQO_AP->head );
    }
    if( rx ){
        mqo_format_cs( s, " :: " );
        mqo_format( s, MQO_RX );
    }

    mqo_format_nl( s );
    mqo_printstr( s );
    mqo_objfree( s );
}
void mqo_chain( mqo_pair data ){
    if( ! MQO_CP ) MQO_CP = mqo_make_callframe( );
    MQO_CP->head = data;
    MQO_CP->tail = mqo_last_pair( data );
    MQO_CP->count = mqo_list_length( data );
    mqo_jump( );
    mqo_interp_loop();
}
void mqo_chainf( mqo_value fn, mqo_word ct, ... ){
    va_list ap;
    mqo_pair tc = mqo_make_tc( );
    va_start( ap, ct );

    mqo_tc_append( tc, fn );

    while( ct -- ){
        mqo_tc_append( tc, va_arg( ap, mqo_value ) );
    }

    mqo_chain( mqo_pair_fv( mqo_car( tc ) ) );
}

void mqo_trace_step( ){
    mqo_trace_ip( MQO_IP );
}
mqo_value mqo_req_function( mqo_value v ){
    if( mqo_is_function( v ) )return v;
    mqo_errf( mqo_es_vm, "sx", "expected function", v );
}

