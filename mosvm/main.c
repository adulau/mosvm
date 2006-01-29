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

#include <gc.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <stdlib.h>
#include <signal.h>
#endif

#include "mosvm.h"
mqo_pair mqo_argv;
mqo_integer mqo_argc;

void mqo_init_mosvm(){
#ifdef NO_PARALLEL_GC
    // Darwin's libgc can deadlock while initializing. We'll take the speed
    // hit over a deadlock any day..
    setenv( "GC_NPROCS", "1", 1 );
#endif
    GC_INIT( );

    mqo_init_memory_subsystem( );
    mqo_init_parse_subsystem();
    mqo_init_exec_subsystem( );
    mqo_bind_core_prims( );
    mqo_bind_os_prims( );
    mqo_bind_progn_prims( );
}

void mqo_handle_sigint( int sig ){
    mqo_newline( );
    mqo_show_cstring( "Interrupted by user." );
    mqo_newline( );
    mqo_show_cstring( "DS: ");
    mqo_dump_stack( MQO_SV, MQO_SI );
    mqo_newline( );
    mqo_show_cstring( "RS: ");
    mqo_dump_stack( MQO_RV, MQO_RI );
    mqo_newline( );
    exit(1);
}
int main( int argc, const char *argv[] ){
    mqo_pair ps, p;
    mqo_init_mosvm();
    int mqo_show_final = 0;
	
#ifdef _WIN32
    char name[MAX_PATH];
    if (GetModuleFileName(NULL,name,sizeof(name))==0){
        mqo_errf(
            mqo_es_vm, "s", "windows cannot identify the location of mosvm"
        );
        return EXIT_FAILURE;
    }
    argv[0]=name;
#endif
	
    mqo_argv = NULL;
	 
    mqo_integer ct = 0;
    ps = mqo_cons( mqo_vf_empty(), mqo_vf_empty() ); 
    for( int i = 0; i < argc; i ++ ){
        if(! strcmp( argv[i], "-d" ) ){
            mqo_trace_vm = ! mqo_trace_vm;
        }else if( ! strcmp( argv[i], "-s" ) ){
            mqo_show_final = ! mqo_show_final;
        }else{
            ct++;
            mqo_tc_append( ps, mqo_vf_string( mqo_string_fs( argv[ i ] ) ) );
        }
    }

    mqo_argc = ct;
    mqo_argv = mqo_pair_fv( mqo_car( ps ) );
#if defined( __CYGWIN__ )
    static char buf[256];
    strcpy( buf, argv[0] );
    strcat( buf, ".exe" );
    argv[0] = buf;
#endif

    ps = mqo_thaw_tail( argv[0] );
    p = NULL;

#if defined( _WIN32 )||defined( __CYGWIN__ )  
#else
    signal( SIGINT, mqo_handle_sigint );
#endif

    mqo_value v, r;

    MQO_FOREACH( ps, p ){
        v = mqo_car( p );

        if( mqo_is_function( v ) ){
            r = mqo_execute( v );
        }else{
            mqo_errf( 
                mqo_es_vm, "sx",
                "Frozen attachment is not a program or procedure.",
                v );
        };
    }


    if( mqo_show_final ){
        mqo_show( r, 32 );
        mqo_newline();
    } 
    
    return mqo_is_false( r ) ? EXIT_FAILURE : EXIT_SUCCESS;
}
