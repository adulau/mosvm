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
#include <sys/time.h>


mqo_timeout mqo_first_timeout = NULL;
mqo_timeout mqo_last_timeout = NULL;
mqo_process mqo_timemon;

int mqo_timeout_compare( mqo_timeout t1, mqo_timeout t2 ){
    if( t1->secs > t2->secs ) return 1;
    if( t1->secs < t2->secs ) return -1;
    if( t1->nsecs < t2->nsecs ) return 1;
    if( t1->nsecs < t2->nsecs ) return -1;
    return 0;
}

/*

void mqo_get_now( mqo_quad* secs, mqo_quad* nsecs ){
    struct timespec ts;
    clock_gettime( CLOCK_REALTIME, &ts );
    *secs = ts.tv_sec;
    *nsecs = ts.tv_nsec;
}

*/

void mqo_get_now( mqo_quad* secs, mqo_quad* nsecs ){
    struct timeval ts;
    gettimeofday( &ts, NULL );
    *secs = ts.tv_sec;
    *nsecs = ts.tv_usec * 1000;
}

mqo_timeout mqo_make_timeout( 
    mqo_quad ms, mqo_channel channel, mqo_value signal  
){
    mqo_quad secs, nsecs; mqo_get_now( &secs, &nsecs );
    secs += (ms / 1000);
    nsecs += ((ms % 1000) * 1000); // 1,000 ns per ms
    mqo_timeout timeout = MQO_OBJALLOC( timeout );
    timeout->secs = secs;
    timeout->nsecs = nsecs;
    timeout->channel = channel;
    timeout->signal = signal;
    return timeout;
}

void mqo_enable_timeout( mqo_timeout new ){
    mqo_timeout timeout, next, prev;

    if( mqo_first_timeout == NULL ){
        mqo_enable_process( mqo_timemon );
    }else for( timeout = mqo_first_timeout; timeout; timeout = next ){
        next = timeout->next;

        if( mqo_timeout_compare( new, timeout ) < 0 ){
            prev = timeout->prev;
            if( prev ){
                prev->next = new;
            }else{
                mqo_first_timeout = new;
            }
            new->prev = prev;
            timeout->prev = new;
            new->next = timeout;

            return;
        }
    }

    if( mqo_last_timeout  ){
        mqo_last_timeout->next = new;
    }else{
        mqo_first_timeout = new;
    }

    new->prev = mqo_last_timeout;
    mqo_last_timeout = new;
}

void mqo_disable_timeout( mqo_timeout timeout ){
    mqo_timeout prev = timeout->prev;
    mqo_timeout next = timeout->next;
    if( prev ){
        prev->next = next;
    }else{
        mqo_first_timeout = next;
    };
    if( next ){
        next->prev = prev;
    }else{
        mqo_last_timeout = prev;
    }
    timeout->prev = timeout->next = NULL;
}
void mqo_trace_timeout( mqo_timeout timeout ){
    mqo_grey_obj( (mqo_object) timeout->channel );
    mqo_grey_val( timeout->signal );
}
void mqo_trace_timeouts( ){
    mqo_timeout timeout, next;
    
    for( timeout = mqo_first_timeout; timeout; timeout = next ){
        next = timeout->next;
        mqo_grey_obj( (mqo_object) timeout );
    }
}
void mqo_invoke_timeout( mqo_timeout timeout ){
    mqo_channel_append( timeout->channel, timeout->signal );
    mqo_disable_timeout( timeout );
}

void mqo_activate_timemon( mqo_process process, mqo_value context ){
    mqo_timeout timeout, next;
    
    mqo_quad secs, nsecs; mqo_get_now( &secs, &nsecs );
    
    for( timeout = mqo_first_timeout; timeout; timeout = next ){
        next = timeout->next;
        if( timeout->secs < secs ){
            mqo_invoke_timeout( timeout );
        }else if( timeout->secs == secs ){
            if( timeout->nsecs <= nsecs ){
                mqo_invoke_timeout( timeout );
            }
        };
    }

    if( mqo_first_timeout == NULL ){
        assert( mqo_last_timeout == NULL );
        mqo_disable_process( mqo_timemon );
    }
}

void mqo_deactivate_timemon( mqo_process process, mqo_value context ){ }

MQO_GENERIC_FORMAT( timeout );
MQO_GENERIC_FREE( timeout );
MQO_C_TYPE( timeout )

MQO_BEGIN_PRIM( "timeout", timeout )
    REQ_INTEGER_ARG( ms );
    REQ_CHANNEL_ARG( channel );
    REQ_ANY_ARG( message );
    NO_REST_ARGS( );
    
    mqo_timeout timeout = ( mqo_make_timeout( ms, channel, message ) ); 
    mqo_enable_timeout( timeout );
    TIMEOUT_RESULT( timeout ); 
MQO_END_PRIM( timeout )

MQO_BEGIN_PRIM( "cancel-timeout", cancel_timeout )
    REQ_TIMEOUT_ARG( timeout )
    NO_REST_ARGS( );
    
    mqo_disable_timeout( timeout );
    
    NO_RESULT( );
MQO_END_PRIM( cancel_timeout )

int mqo_any_timeouts( ){
    return mqo_first_timeout != NULL;
}

void mqo_init_time_subsystem( ){
    MQO_I_TYPE( timeout );
    mqo_timemon = mqo_make_process( 
        (mqo_proc_fn) mqo_activate_timemon, 
        (mqo_proc_fn) mqo_deactivate_timemon, 
        mqo_vf_null( ) 
    );
    mqo_root_obj( (mqo_object) mqo_timemon );
    MQO_BIND_PRIM( timeout );
    MQO_BIND_PRIM( cancel_timeout );
}

