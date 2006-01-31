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

#ifndef MQO_EXEC_H
#define MQO_EXEC_H 1

#include "memory.h"
#include <setjmp.h>

// Called when an error indicates that a non-local exit is required.

#define MQO_NEXT_INSTR 101
#define MQO_NEXT_PROC  102
#define MQO_NEXT_LIFE  200

// A non-local return without restoring the environment from the return stack.
#define MQO_CONTINUE( )  longjmp( *MQO_XP, MQO_NEXT_INSTR );

// Indicates the need for an immediate termination of the process.
#define MQO_HALT( )      ({ MQO_PP->status = mqo_ps_halted; \
                            mqo_unsched_process( MQO_PP ); \
                            longjmp( *MQO_XP, MQO_NEXT_PROC ); });

#define MQO_PAUSE( )     ({ MQO_PP->status = mqo_ps_paused; \
                            longjmp( *MQO_XP, MQO_NEXT_PROC ); })

#define MQO_SUSPEND( )   ({ MQO_PP->status = mqo_ps_suspended; \
                            mqo_unsched_process( MQO_PP ); \
                            longjmp( *MQO_XP, MQO_NEXT_PROC ); })

// Used for non-local returns.
#define MQO_RETURN( )    mqo_return(); MQO_CONTINUE( );

extern jmp_buf* MQO_XP;

extern mqo_integer mqodv;

extern mqo_program  MQO_CP; // The current program.

extern mqo_vector  MQO_SV; // The vector containing the current stack.

extern mqo_integer MQO_SI; // The offset of the top of the current stack in SV.

extern mqo_vector  MQO_RV; // The vector containing continuations.

extern mqo_integer MQO_RI; // The offset of the last continuation in RV.

extern mqo_pair    MQO_EP; // The environment pair chain.

extern mqo_pair    MQO_GP; // The guard pair chain.

extern mqo_instruction MQO_IP; // Next instruction.

extern mqo_process MQO_PP; // The current process.

#define MQO_STACK_SZ 16384

struct mqo_op_row{
    const char* name;
    mqo_prim_fn fn;
    int use_sy:1;
    int use_va:1;
    int use_w1:1;
    int use_w2:1;
    mqo_prim prim;
};
extern struct mqo_op_row mqo_op_table[];

// Employed by primitives like apply and call_op.
void mqo_call( mqo_value fn );
void mqo_return( );
void mqo_tail_call( mqo_value fn );

//NOTE: Use for mqo_exec from within a primitive must be considered a tail
//      call; mosvm will long jump its way back up to the top level exec
//      when it detects that MQO_XP has been assigned.
void mqo_exec( mqo_value value );

//A convenient wrapper for mqo_exec that provides an top level entry for
//executing a function in the virtual machine.  FIX: This will, in turn,
//suspend the active process if is running, spawn a new one, and cycle 
//until the newly created process halts.
//
//The top value on the data stack is then returned.

mqo_value mqo_execute( mqo_value value );

//Creates a new process, configured to evaluate the supplied function when
//it is resumed.  Note, if the supplied function is a primitive, it will be
//executed immediately within the context of the process, as a process can
//only suspend between instructions.

mqo_process mqo_spawn( mqo_value function );

// Sets the auto_suspension parameter of the specified process to the supplied
// count.  If the process performs count instructions without suspending, it
// will automatically suspend.
//TODO/A3
//void mqo_auto_suspend( mqo_process process, mqo_integer count )

// Sets the auto_termination parameter of the specified process to the supplied
// count.  If the process performs count instructions without halting, it
// will automatically halt.
//TODO/A3
//void mqo_auto_halt( mqo_process process, mqo_integer count )

// Q: What is the difference between HALT and SUSPEND?
// A: A process marked as halted may not be resumed.  A suspended process may
//    be resumed.  If, for example, a process must wait for an extended period
//    until a particular condition is satisfied, it would be halted -- 
//    preventing mqo_continue from resuming it until another process indicated
//    that the condition was set.
//    
//    Processes may also halt if they encounter a fatal error.

void mqo_prim_stop_op( );
void mqo_prim_ldc_op( );
void mqo_prim_ldg_op( );
void mqo_prim_ldb_op( );
void mqo_prim_ldf_op( );
void mqo_prim_stg_op( );
void mqo_prim_stb_op( );
void mqo_prim_jmp_op( );
void mqo_prim_jf_op( );
void mqo_prim_jt_op( );
void mqo_prim_call_op( );
void mqo_prim_tail_op( );
void mqo_prim_retn_op( );
void mqo_prim_usen_op( );
void mqo_prim_usea_op( );
void mqo_prim_ldu_op( );
void mqo_prim_drop_op( );
void mqo_prim_copy_op( );
void mqo_prim_gar_op( );
void mqo_prim_rag_op( );

// The following two functions signal that an error has occurred.  They will
// never return, since they will result in a non-local jump upwards into the
// top level execution loop followed by a call to the current guard procedure.
void mqo_err( mqo_symbol key, mqo_pair info );
void mqo_errf( mqo_symbol key, const char* fmt, ... );

void mqo_il_traceback( mqo_error err );
void mqo_dump_stack( mqo_vector sv, mqo_integer si );

void mqo_bind_core_prims();
void mqo_bind_os_prims();
void mqo_bind_progn_prims();
void mqo_init_exec_subsystem();

extern mqo_symbol mqo_es_vm;
extern mqo_symbol mqo_es_args;

extern mqo_symbol mqo_ps_suspended;
extern mqo_symbol mqo_ps_running;
extern mqo_symbol mqo_ps_halted;
extern mqo_symbol mqo_ps_paused;

extern mqo_process mqo_first_process;
extern mqo_process mqo_last_process;

void mqo_use_process( mqo_process process );
// Rotates in the specified process, rotating out the old one.

void mqo_resched_process( mqo_process process );
// Ensures the supplied process is scheduled for execution.

void mqo_unsched_process( mqo_process process );
// Ensures the supplied process is not scheduled for execution.

void mqo_resume( mqo_process process, mqo_value value );

extern mqo_boolean mqo_trace_vm;

void mqo_report_os_error( );
int mqo_os_error( int code );
#endif

