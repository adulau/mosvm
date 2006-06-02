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
#include <stdarg.h>

int mqo_abort_on_error = 0;

void mqo_format_error( mqo_string buf, mqo_error e ){
    mqo_format_begin( buf, e );
    mqo_format_char( buf, ' ' );
    mqo_format_sym( buf, e->key );
    mqo_format_items( buf, e->info, 1 );
    mqo_format_end( buf );
}

int mqo_format_context( mqo_string buf, mqo_list context  ){
    if( context == NULL )return 0; 
    
    if( mqo_format_context( buf, mqo_list_fv( mqo_cdr( context ) ) ) ){ 
        mqo_format_indent( buf, 11 ); 
    }else{ 
        mqo_format_cs( buf, "TRACEBACK: " ); 
    };
    
    mqo_format( buf, mqo_car( context ) );
    mqo_format_nl( buf );

    return 1;
}

void mqo_format_traceback( mqo_string buf, mqo_error e ){
    mqo_pair p;
    
    mqo_format_cs( buf, "ERROR: " );
    mqo_format_sym( buf, e->key );

    p = e->info;

    if( p ){
        mqo_value v = mqo_car( e->info );
        if( mqo_is_string( v ) ){
            mqo_format_cs( buf, "--" );
            mqo_format_str( buf, mqo_string_fv( v ) );
            mqo_format_nl( buf );
            mqo_format_cs( buf, "       " );
            
            if( mqo_is_list( mqo_cdr( p ) ) ){
                p = mqo_list_fv( mqo_cdr( p ) );
            }else{
                p = NULL;
            }
        }else{
            mqo_format_cs( buf, " :: " );
        };

        mqo_format_items( buf, p, 0 );
    };

    mqo_format_nl( buf );
    mqo_format_context( buf, e->context );
}

mqo_error mqo_make_error( mqo_symbol key, mqo_list info, mqo_list context ){
    mqo_error e = MQO_OBJALLOC( error );
    e->key = key;
    e->info = info;
    e->context = context;
    return e;
}

mqo_list mqo_frame_context( mqo_callframe cp ){
    mqo_pair t1 = mqo_make_tc( );

    while( cp ){
        mqo_tc_append( t1, mqo_vf_pair( cp->head ) );
        cp = cp->cp;
    }

    return mqo_list_fv( mqo_car( t1 ) );
}

void mqo_trace_error( mqo_error e ){
    mqo_grey_obj( (mqo_object) e->key );
    mqo_grey_obj( (mqo_object) e->info );
    mqo_grey_obj( (mqo_object) e->context );
}

void mqo_throw_error( mqo_error e ){
    if( MQO_GP ){
        mqo_guard g = mqo_guard_fv( mqo_car( MQO_GP ) );
        MQO_GP = mqo_list_fv( mqo_cdr( MQO_GP ) );
        MQO_CP = g->cp;
        MQO_EP = g->ep;
        MQO_IP = g->ip;
        
        MQO_AP = mqo_make_callframe( );
        MQO_AP->cp = MQO_CP;
        MQO_AP->ep = MQO_EP;
        MQO_AP->ip = MQO_IP;
        MQO_CP = MQO_AP;

        mqo_chainf( g->fn, 1, e );
    }else{
        mqo_string s = mqo_make_string( 128 );
        mqo_format_traceback( s, e ); 
        mqo_printstr( s );
        if( mqo_abort_on_error ){
            abort( );
        }else{
            exit( 1 );
        }
    }
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
            value = mqo_vf_string( mqo_string_fs( va_arg( ap, const char* ) ) );
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
        };

        item = mqo_cons( value, mqo_vf_null( ) );
        if( tail ){
            mqo_set_cdr( tail, mqo_vf_pair( item ) );
        }else{
            head = item;
        };
        tail = item;
    }
done:
    va_end( ap );
    mqo_throw_error( mqo_make_error( key, head, mqo_frame_context( MQO_CP ) ) );
}

MQO_GENERIC_COMPARE( error );
MQO_GENERIC_FREE( error );
MQO_C_TYPE( error );

mqo_guard mqo_make_guard( 
    mqo_value fn, mqo_callframe cp, mqo_callframe ap, mqo_pair ep, 
    mqo_instruction ip
){
    mqo_guard g = MQO_OBJALLOC( guard );

    g->fn = fn;
    g->ap = ap;
    g->cp = cp;
    g->ip = ip;
    g->ep = ep;

    return g;
}
void mqo_format_guard( mqo_string buf, mqo_guard guard ){
    mqo_format_begin( buf, guard );
    mqo_format_char( buf, ' ' );
    mqo_format_func( buf, guard->fn );
    mqo_format_end( buf );
}
void mqo_trace_guard( mqo_guard guard ){
    mqo_grey_val( guard->fn );
    mqo_grey_obj( (mqo_object) guard->cp );
    mqo_grey_obj( (mqo_object) guard->ap );
    mqo_grey_obj( (mqo_object) guard->ep );
    if( guard->ip )mqo_grey_obj( (mqo_object) guard->ip->proc );
}
MQO_GENERIC_FREE( guard );
MQO_GENERIC_COMPARE( guard );
MQO_C_TYPE( guard );

MQO_BEGIN_PRIM( "error", error )
    REQ_SYMBOL_ARG( key );
    REST_ARGS( info );
    
    mqo_error err = mqo_make_error( key, info, 
                                    mqo_frame_context( MQO_CP ) );

    mqo_throw_error( err );
MQO_END_PRIM( error )

MQO_BEGIN_PRIM( "traceback", traceback )
    REQ_ERROR_ARG( error );
    NO_REST_ARGS( );
    
    mqo_string s = mqo_make_string( 128 );
    mqo_format_traceback( s, error );
    mqo_printstr( s );
    mqo_objfree( s );

    NO_RESULT( );
MQO_END_PRIM( error )

MQO_BEGIN_PRIM( "re-error", re_error )
    REQ_ERROR_ARG( error );
    NO_REST_ARGS( );
    
    mqo_throw_error( error );

    NO_RESULT( );
MQO_END_PRIM( re_error )

void mqo_init_error_subsystem( ){
    MQO_I_TYPE( error );
    MQO_I_TYPE( guard );
    MQO_BIND_PRIM( error );
    MQO_BIND_PRIM( traceback );
    MQO_BIND_PRIM( re_error );
}

