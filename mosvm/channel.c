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
mqo_channel mqo_make_channel( ){
    mqo_channel c = MQO_OBJALLOC( channel );
    return c;
}
void mqo_trace_channel( mqo_channel channel ){
    // The first_mon will mark all peers.
    mqo_grey_obj( (mqo_object) channel->first_mon );

    mqo_grey_obj( (mqo_object) channel->head );
    mqo_grey_obj( (mqo_object) channel->tail );
    mqo_grey_val( channel->source );
}

void mqo_trip_source( mqo_channel channel ){
    if( mqo_is_stream( channel->source ) ){
        mqo_enable_stream( mqo_stream_fv( channel->source ) );
    }
}

void mqo_add_monitor( mqo_process process, mqo_channel channel ){
    if( process->monitoring ){
        mqo_errf( mqo_es_vm, "sxxx", 
                "a process may only monitor one channel at a time",
                process, 
                process->monitoring,
                channel );
    };

    mqo_disable_process( process );
    process->monitoring = (mqo_object) channel;
   
    mqo_process prev = channel->last_mon;
    process->prev = prev;

    if( prev ){
        prev->next = process;
    }else{
        channel->first_mon = process;
    };
    
    channel->last_mon = process;

    mqo_trip_source( channel );
}

void mqo_remove_monitor( mqo_process process, mqo_channel channel ){
    mqo_process first, prev, next;

    assert( channel == (mqo_channel)process->monitoring );

    first = channel->first_mon;
    next = process->next;
    prev = process->prev;

    assert( first );

    if( prev ){ prev->next = next; process->prev = NULL; }else{
        channel->first_mon = next;
    };
    if( next ){ next->prev = prev; process->next = NULL; }else{
        channel->last_mon = prev;
    };

    process->monitoring = NULL;
}

void mqo_clear_monitor( mqo_process process ){
    mqo_remove_monitor( process, (mqo_channel) process->monitoring );
}

mqo_boolean mqo_wake_monitor( mqo_channel channel, mqo_value message ){
    mqo_process process = channel->first_mon;

    if( process ){ 
        mqo_clear_monitor( process );
        mqo_enable_process( process );
        if( mqo_is_vm( process->context ) ){
            // A courtesy to vm processes..
            mqo_vm_fv( process->context )->rx = message;
            return 1;
        }
    }

    return 0;
}

void mqo_channel_append( mqo_channel channel, mqo_value message ){
    if( mqo_wake_monitor( channel, message ) )return;

    mqo_pair p = mqo_cons( message, mqo_vf_null() );

    if( channel->head ){
        mqo_set_cdr( channel->tail, mqo_vf_pair( p ) );
    }else{
        channel->head = p;
    }

    channel->tail = p;
}

void mqo_channel_prepend( mqo_channel channel, mqo_value message ){
    if( mqo_wake_monitor( channel, message ) )return;
    if( mqo_wake_monitor( channel, message ) )return;

    mqo_pair p = mqo_cons( message, mqo_vf_list( channel->head ) );

    if( ! channel->tail ) channel->tail = p;

    channel->head = p;
}

mqo_boolean mqo_channel_empty( mqo_channel channel ){
    return channel->head == NULL;
}
mqo_value mqo_read_channel( mqo_channel channel ){
    if( mqo_channel_empty( channel ) ) return mqo_vf_null();

    mqo_pair next, head = channel->head;

    next = mqo_list_fv( mqo_cdr( head ) );

    if( next ){
        channel->head = next;
    }else{
        channel->head = channel->tail = NULL;
    }

    return mqo_car( head );
}
mqo_value mqo_channel_head( mqo_channel channel ){
    if( mqo_channel_empty( channel ) ) return mqo_vf_null();
    return mqo_car( channel->head );
}
mqo_value mqo_channel_tail( mqo_channel channel ){
    if( mqo_channel_empty( channel ) ) return mqo_vf_null();
    return mqo_car( channel->tail );
}

mqo_channel mqo_get_output( mqo_value x ){
    if( mqo_is_stream( x ) ){
        return mqo_stream_output( mqo_stream_fv( x ) );
    }else if( mqo_is_channel( x ) ){
        return mqo_channel_fv( x );
    }else if( mqo_is_process( x ) ){
        return (mqo_channel)mqo_process_output( mqo_process_fv( x ) );
    }else if( mqo_is_listener( x ) ){
        return mqo_listener_output( mqo_listener_fv( x ) );
    }else{
        return NULL;
    }
}

mqo_channel mqo_req_output( mqo_value x ){
    mqo_channel c = mqo_get_output( x );
    if( c == NULL ){
        mqo_errf( mqo_es_vm, "sx", "cannot determine output channel", x );
    }else{
        return c;
    }
}

void mqo_set_output( mqo_value x, mqo_channel output ){
    if( mqo_is_stream( x ) ){
        mqo_set_stream_output( mqo_stream_fv( x ), output );
    }else if( mqo_is_process( x ) ){
        mqo_set_process_output( mqo_process_fv( x ), (mqo_object) output );
    }else{
        mqo_errf( mqo_es_vm, "sx", "cannot assign output channel", x );
    }
}

mqo_channel mqo_get_input( mqo_value x ){
    if( mqo_is_stream( x ) ){
        return mqo_stream_input( mqo_stream_fv( x ) );
    }else if( mqo_is_channel( x ) ){
        return mqo_channel_fv( x );
    }else if( mqo_is_process( x ) ){
        return (mqo_channel)mqo_process_input( mqo_process_fv( x ) );
    }else{
        return NULL;
    }
}

mqo_channel mqo_get_channel( mqo_value x ){
    mqo_channel c;
    c = mqo_get_input( x );
    if( c ) return c;
    c = mqo_get_output( x );
    if( c ) return c;
    return NULL;
}
mqo_channel mqo_req_input( mqo_value x ){
    mqo_channel c = mqo_get_input( x );
    if( c == NULL ){
        mqo_errf( mqo_es_vm, "sx", "cannot determine input channel", x );
    }else{
        return c;
    }
}

void mqo_set_input( mqo_value x, mqo_channel input ){
    if( mqo_is_stream( x ) ){
        return mqo_set_stream_input( mqo_stream_fv( x ), input );
    }else if( mqo_is_process( x ) ){
        return mqo_set_process_input( mqo_process_fv( x ), (mqo_object) input );
    }else{
        mqo_errf( mqo_es_vm, "sx", "cannot assign input channel", x );
    }
}

MQO_GENERIC_COMPARE( channel );

MQO_GENERIC_FORMAT( channel );
MQO_GENERIC_FREE( channel );
MQO_C_TYPE( channel )

MQO_BEGIN_PRIM( "send", send )
    REQ_ANY_ARG( message );
    REST_ARGS( channels );
    
    if( ! channels ){
        channels = mqo_cons( mqo_vf_obj(  mqo_active_process->output ),
                             mqo_vf_null() );
    };

    while( channels ){
        mqo_channel_append( mqo_req_input( mqo_car( channels ) ), 
                            message );
        channels = mqo_req_list( mqo_cdr( channels ) );
    }

    NO_RESULT( );
MQO_END_PRIM( send )

MQO_BEGIN_PRIM( "channel-empty?", channel_emptyq )
    REQ_CHANNEL_ARG( channel );
    NO_REST_ARGS( );
    
    BOOLEAN_RESULT( mqo_channel_empty( channel ) );
MQO_END_PRIM( channel_emptyq )

MQO_BEGIN_PRIM( "wait", wait )
    OPT_OUTPUT_ARG( channel );
    NO_REST_ARGS( );

    if( ! has_channel ){ channel = (mqo_channel) mqo_active_process->input; };
    assert( channel );

    if( mqo_channel_empty( channel ) ){
        mqo_add_monitor( mqo_active_process, channel );

        MQO_CP = MQO_CP->cp;
        mqo_proc_loop( );
        NO_RESULT( );
    }else{
        RESULT( mqo_read_channel( channel ) );
    }
MQO_END_PRIM( wait )

MQO_BEGIN_PRIM( "make-channel", make_channel )
    NO_REST_ARGS( );

    CHANNEL_RESULT( mqo_make_channel( ) );
MQO_END_PRIM( make_channel )

MQO_BEGIN_PRIM( "waiting?", waitingq )
    REQ_PROCESS_ARG( process );
    OPT_CHANNEL_ARG( channel );
    NO_REST_ARGS( );
    
    if( has_channel ){
        BOOLEAN_RESULT( ((mqo_channel) process->monitoring ) == channel );
    }else{
        BOOLEAN_RESULT( process->monitoring != NULL ); 
    }
MQO_END_PRIM( waitingq )

MQO_BEGIN_PRIM( "set-input!", set_input )
    REQ_ANY_ARG( arg1 );
    OPT_ANY_ARG( arg2 );
    NO_REST_ARGS( );
    
    mqo_value value; 
    mqo_channel channel;

    if( has_arg2 ){
        value = arg1;
        channel = mqo_get_input( arg2 );
    }else{
        value = mqo_vf_process( mqo_active_process );
        channel = mqo_get_input( arg1 );
    }
    mqo_set_input( value, channel );

    RESULT( value );
MQO_END_PRIM( set_input )

MQO_BEGIN_PRIM( "set-output!", set_output )
    REQ_ANY_ARG( arg1 );
    OPT_ANY_ARG( arg2 );
    NO_REST_ARGS( );
    
    mqo_value value; 
    mqo_channel channel;

    if( has_arg2 ){
        value = arg1;
        channel = mqo_get_output( arg2 );
    }else{
        value = mqo_vf_process( mqo_active_process );
        channel = mqo_get_output( arg1 );
    }

    mqo_set_output( value, channel );

    RESULT( value );
MQO_END_PRIM( set_output )

MQO_BEGIN_PRIM( "input", input )
    OPT_INPUT_ARG( channel );
    NO_REST_ARGS( );

    if( ! has_channel ){
        channel = mqo_req_input( mqo_vf_process( mqo_active_process ) );
    }

    CHANNEL_RESULT( channel );
MQO_END_PRIM( input )

MQO_BEGIN_PRIM( "output", output )
    OPT_OUTPUT_ARG( channel );
    NO_REST_ARGS( );

    if( ! has_channel ){
        channel = mqo_req_output( mqo_vf_process( mqo_active_process ) );
    }

    CHANNEL_RESULT( channel );
MQO_END_PRIM( output )

MQO_BEGIN_PRIM( "input?", inputq )
    OPT_ANY_ARG( value );
    NO_REST_ARGS( );
    if( ! has_value ) value = mqo_vf_process( mqo_active_process );
    mqo_channel channel = mqo_get_input( value );
    RESULT( channel ? mqo_vf_channel( channel ) : mqo_vf_false( ) );
MQO_END_PRIM( input )

MQO_BEGIN_PRIM( "output?", outputq )
    OPT_ANY_ARG( value );
    NO_REST_ARGS( );
    if( ! has_value ) value = mqo_vf_process( mqo_active_process );
    mqo_channel channel = mqo_get_output( value );
    RESULT( channel ? mqo_vf_channel( channel ) : mqo_vf_false( ) );
MQO_END_PRIM( output )

void mqo_init_channel_subsystem( ){
    MQO_I_TYPE( channel );
    MQO_BIND_PRIM( wait );
    MQO_BIND_PRIM( waitingq );
    MQO_BIND_PRIM( send );
    MQO_BIND_PRIM( channel_emptyq );
    MQO_BIND_PRIM( make_channel );
    MQO_BIND_PRIM( input );
    MQO_BIND_PRIM( output );
    MQO_BIND_PRIM( set_input );
    MQO_BIND_PRIM( set_output );
    MQO_BIND_PRIM( inputq );
    MQO_BIND_PRIM( outputq );
}
