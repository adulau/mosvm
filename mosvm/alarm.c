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

//TODO: Insulator for WIN32
#include <string.h>

#if defined(_WIN32)||defined(__CYGWIN__)
#include <sys/time.h>
#include <winsock2.h>
#else
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#endif

#include "mosvm.h"

mqo_symbol mqo_as_read;
mqo_symbol mqo_as_write;

mqo_tree mqo_read_alarms;
mqo_tree mqo_write_alarms;

mqo_alarm mqo_make_alarm( mqo_symbol type, mqo_process process, 
                          mqo_descr descr ){
    mqo_alarm alarm = MQO_ALLOC( mqo_alarm, 0 );
    alarm->type = type;
    alarm->process = process;
    alarm->descr = descr;
    return alarm;                    
}
void mqo_enable_alarm( mqo_alarm alarm ){
    if( mqo_is_read_alarm( alarm ) ){ 
        mqo_tree_insert( mqo_read_alarms, mqo_vf_alarm( alarm ) );
    }else if( mqo_is_write_alarm( alarm ) ){
        mqo_tree_insert( mqo_write_alarms, mqo_vf_alarm( alarm ) );
    }else{
        //TODO: Signal error.
    }
}
void mqo_disable_alarm( mqo_alarm alarm ){
    if( mqo_is_read_alarm( alarm ) ){ 
        mqo_tree_remove( mqo_read_alarms, mqo_vf_alarm( alarm ) );
    }else if( mqo_is_write_alarm( alarm ) ){
        mqo_tree_remove( mqo_write_alarms, mqo_vf_alarm( alarm  ) );
    }else{
        //TODO: Signal error.
    }
}
int mqo_process_alarms( ){
    static struct timeval timeout_data = { 0, 0 };
   
    struct timeval *timeout;
    struct fd_set reads, writes, errors;
    mqo_alarm alarm;
    mqo_node node;
    int fd, maxfd;

    if( mqo_first_process ){
        timeout = &timeout_data;
    }else{
        //TODO: This should be modified by the window of the next timed
        //      alarm.
        timeout = NULL;
    }
    
    FD_ZERO( &reads );
    FD_ZERO( &writes );
    FD_ZERO( &errors );
    maxfd = -1;

    node = mqo_first_node( mqo_read_alarms );
    while( node = mqo_next_node( node ) ){
        alarm = mqo_alarm_fv( node->data );
        fd = alarm->descr->fd;
        if( fd > maxfd ) maxfd = fd;
        FD_SET( fd, &reads );
        FD_SET( fd, &errors );
    }

    node = mqo_first_node( mqo_write_alarms );
    while( node = mqo_next_node( node ) ){
        alarm = mqo_alarm_fv( node->data );
        fd = alarm->descr->fd;
        if( fd > maxfd ) maxfd = fd;
        FD_SET( fd, &writes );
        FD_SET( fd, &errors );
    }
   
    //TODO: We need to make sure maxfd wasn't greater than FD_SETSIZE, a fatal
    //      error for select loops.

    if( maxfd == -1 ) return 0;

    //TODO: We should watch for an error, here.
    select( maxfd + 1, &reads, &writes, &errors, timeout );

    node = mqo_first_node( mqo_read_alarms );
    while( node = mqo_next_node( node ) ){
        alarm = mqo_alarm_fv( node->data );
        fd = alarm->descr->fd;
        if( FD_ISSET( fd, &reads ) || FD_ISSET( fd, &errors ) ){ 
            mqo_resume( alarm->process, mqo_vf_alarm( alarm ) );
        }
    }
    
    node = mqo_first_node( mqo_write_alarms );
    while( node = mqo_next_node( node ) ){
        alarm = mqo_alarm_fv( node->data );
        fd = alarm->descr->fd;
        if( FD_ISSET( fd, &writes ) || FD_ISSET( fd, &errors ) ){ 
            mqo_resume( alarm->process, mqo_vf_alarm( alarm ) );
        }
    }

    return 1;
}

MQO_DEFN_TYPE( alarm );

void mqo_init_alarm_subsystem( ){
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup( 2, &wsa );
#endif
    MQO_BIND_TYPE( alarm, NULL, NULL );
    mqo_read_alarms = mqo_make_tree( mqo_set_key );
    mqo_write_alarms = mqo_make_tree( mqo_set_key );
}

