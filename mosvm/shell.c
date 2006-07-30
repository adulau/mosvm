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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include "mosvm.h"


//TODO: This will not work on win32.
extern char** environ;

int mqo_scan_argv( mqo_list arglist ){
    mqo_list list = arglist;
    int ct = 0;

    while( list ){
        ct ++;
        if( ! mqo_is_string( mqo_car( list ) ) ){
            mqo_errf( mqo_es_vm, "sx", "expected list of strings", arglist );
        };
        if( ! mqo_is_pair( mqo_cdr( list ) ) )break;
        list = mqo_list_fv( mqo_cdr( list ) );
    }

    return ct;
}
char** mqo_make_argv( mqo_list arglist, int ct ){
    char** argv = (char**) malloc( ( ct + 1 ) * sizeof( char* ) );
    mqo_list list = arglist;
    ct = 0;

    while( list ){
        argv[ct++] = mqo_sf_string( mqo_string_fv( mqo_car( list ) ) );
        list = mqo_list_fv( mqo_cdr( list ) );
    }
    
    argv[ct] = NULL;

    return argv;
}
#ifndef _WIN32
#include <sys/socket.h>
// spawn_cmd not defined for win32, yet.
mqo_stream mqo_spawn_cmd( mqo_string path, mqo_list arg, mqo_list var ){
    int argc = mqo_scan_argv( arg );
    int varc = mqo_scan_argv( var );

    int fds[2];

    arg = mqo_cons( mqo_vf_string( path ), mqo_vf_list( arg ) );

    mqo_os_error( socketpair( AF_LOCAL, SOCK_STREAM, 0, fds ) ); 

    char** argv = mqo_make_argv( arg, argc );
    char** varv = varc ? mqo_make_argv( var, varc ) : environ;

    int pid = fork(); 

    if( pid ){
        free( argv );
        if( varc )free( varv );
        mqo_os_error( pid );
        close( fds[1] );
        return mqo_make_stream( fds[0] );
    }else{
        close( fds[0] );
        // Awww yeah.. Duping and forking like it's 1986..
        dup2( fds[1], STDIN_FILENO );
        dup2( fds[1], STDOUT_FILENO );
        
        execve( mqo_sf_string( path ), argv, varv );
        // We shouldn't be here, but here we are..
        close( fds[1] );
        _exit(0);
    }
}

MQO_BEGIN_PRIM( "spawn-command", spawn_command );
    REQ_STRING_ARG( path );
    OPT_LIST_ARG( args );
    OPT_LIST_ARG( env );
    NO_REST_ARGS( );
    
    STREAM_RESULT( mqo_spawn_cmd( path, args, env ) );
MQO_END_PRIM( spawn_command );
#endif

MQO_BEGIN_PRIM( "run-command", run_command );
    REQ_STRING_ARG( command );
    NO_REST_ARGS( );
    
    INTEGER_RESULT( mqo_os_error( system( mqo_sf_string( command ) ) ) );
MQO_END_PRIM( spawn_command );

void mqo_init_shell_subsystem( ){
#ifndef _WIN32
// spawn_cmd not defined for win32, yet.
    MQO_BIND_PRIM( spawn_command );
#endif

    MQO_BIND_PRIM( run_command );
    char** env = environ;
    mqo_tc tc = mqo_make_tc( );
    while( *env ){
        mqo_tc_append( tc, mqo_vf_string( mqo_string_fs( *env ) ) );
        env++;
    }
    mqo_set_global( mqo_symbol_fs( "*environ*" ), mqo_car( tc ) );
}
