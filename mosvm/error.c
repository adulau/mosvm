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
#include <stdarg.h>
#include <errno.h>

#define MQO_CRASH_UNLESS( cond ) (cond)||mqo_crash( NULL );
int mqo_crash( const char* msg ){
    mqo_newline( );
    if( msg ){
        mqo_write( msg );
    }else{
        mqo_write(
            "A fatal error has occurred in a place that"
            " MOSVM cannot explain."
        );
    };
    mqo_newline( );
    abort( );
    return 0;
}
void mqo_dump_error( mqo_error e ){
    mqo_write( "Error: " );
    mqo_writesym( e->key );
    MQO_FOREACH( e->info, item ){
        mqo_writech( ' ' );
        mqo_word ct = 16; mqo_show( mqo_car( item ), &ct );
    }
    mqo_newline( );
    MQO_FOREACH( e->context, frame ){
        mqo_write( "       "  );
        mqo_word ct = 16; mqo_show( mqo_car( frame ), &ct );
        mqo_newline( );
    }
}
void mqo_raise( mqo_symbol key, mqo_pair info ){
    mqo_vector  rv = MQO_RV;
    mqo_vector  sv = MQO_SV;
    mqo_integer ri = MQO_RI;
    mqo_integer si = MQO_SI;
    mqo_pair    ep = MQO_EP;

    mqo_value*  argv;
    mqo_integer i, argc = 0;

    mqo_value fn, x;
    
    mqo_pair frame;
    mqo_pair frames = NULL;

    MQO_CRASH_UNLESS( ( ri <= 1 )||( ri > 4 ) );

    while( ri > 1 ){ //Note, there's always one base RI from the executing
                     //program.
        frame = mqo_make_tc( );

        MQO_CRASH_UNLESS( ri > 4 );

        x = mqo_vector_get( rv, --ri );
        MQO_CRASH_UNLESS( mqo_is_integer( x ) );
        argc = mqo_integer_fv( x );

        fn = mqo_vector_get( rv, --ri );
        MQO_CRASH_UNLESS( mqo_is_function( fn ) );

        mqo_tc_append( frame, fn );

        if( mqo_is_closure( fn ) ){
            if( argc ){
                argv = mqo_vector_ref( mqo_vector_fv( mqo_car( ep ) ), 0 );
            }else{
                argv = NULL;
            }
        }else if( argc ){
            si = si - argc - 1;
            argv = mqo_vector_ref( sv, si );
        }else{
            argv = NULL;
        }

        for( int i = 0; i < argc; i ++ ){
            mqo_tc_append( frame, argv[i] );
        }

        frames = mqo_cons( mqo_car( frame ), mqo_vf_pair( frames ) );
        
        x = mqo_vector_get( rv,  --ri );
        MQO_CRASH_UNLESS( mqo_is_pair( x ) );
        ep = mqo_pair_fv( x );

        ri -= 2;
    }
    
    mqo_error err = mqo_make_error( key, info, frames );
    mqo_throw( err );
}

void mqo_throw( mqo_error err ){
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
        //mqo_dump_stack( MQO_SV, MQO_SI );
        //mqo_dump_stack( MQO_RV, MQO_RI );
        mqo_dump_error( err );
        MQO_IP = NULL;
        MQO_EP = NULL;
        MQO_SI = MQO_RI = 0;
        MQO_HALT( );
    }
}

mqo_error mqo_make_error( mqo_symbol key, mqo_pair info, mqo_pair context ){
    mqo_error e = MQO_ALLOC( mqo_error, 0 );

    e->key = key;
    e->info = info;
    e->context = context;

    return e;
}
mqo_guard mqo_make_guard( 
    mqo_value fn, mqo_integer ri, mqo_integer si, 
    mqo_program cp,  mqo_instruction ip, mqo_pair ep
){
    mqo_guard e = MQO_ALLOC( mqo_guard, 0 );

    e->fn = fn;
    e->ri = ri;
    e->si = si;
    e->cp = cp;
    e->ip = ip;
    e->ep = ep;

    return e;
}
void mqo_show_error( mqo_error e, mqo_word* ct ){
    if( ! e ){ mqo_show_unknown( mqo_error_type, 0 ); return; }
    mqo_write( "[error " );
    mqo_writesym( e->key );
    mqo_show_pair_contents( e->info, ct );
    mqo_write( "]" );
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
    mqo_raise( key, head );
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
