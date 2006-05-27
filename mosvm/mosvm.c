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
#include <string.h>

#ifdef _WIN32
#else
#include <signal.h>

//TODO: Add (disable-sigint) so the drone can block this.
void mqo_handle_sigint( int sig ){
    mqo_newline( );
    mqo_print( "Interrupted by user." );
    mqo_newline( );
    mqo_traceback_frame( mqo_frame_context( MQO_CP ) );
    mqo_newline( );
    exit(909);
}
#endif

void mqo_run( mqo_value func ){
    // TODO: Retire when process is back in.
    mqo_spawn_func( func );
    mqo_proc_loop( );
}

int main( int argc, const char** argv ){
#ifdef _WIN32
    char name[MAX_PATH];
    if (GetModuleFileName(NULL,name,sizeof(name))==0){
        mqo_errf(
            mqo_es_vm, "s", "windows cannot identify the location of mosvm"
        );
        return EXIT_FAILURE;
    }
    argv[0]=name;
#else
    signal( SIGINT, mqo_handle_sigint );
#endif

    mqo_init_mosvm( );
/*
    if( argc > 1 ){ 
        int i;
        for( i = 1; i < argc; i ++ ){
            mqo_value x;

            if( ! strcmp( argv[i], "-d" ) ){
                mqo_trace_flag = ! mqo_trace_flag; 
            }else if( ! strcmp( argv[i], "-g" ) ){
                mqo_word ct = 65535;
                mqo_show( mqo_vf_pair( mqo_get_globals( ) ), &ct );
            }else{ 
                x = mqo_thaw_str( mqo_read_file( argv[i] ) );
                if( mqo_is_function( x ) ){
                    mqo_run( x );
                }else{
                    mqo_word ct = 100; mqo_show( x, &ct );
                    mqo_newline();
                }
            }
        }
    }else{
        mqo_print( argv[0] );
        mqo_print( " objfile1 objfile2 ...\n" );
        mqo_print( "Executes each object file in turn.\n" );
    }
*/
    mqo_argv = mqo_make_tc( );
    mqo_argc = 0;
    int i, mqo_show_globals = 0;
    for( i = 1; i < argc; i ++ ){
        if( ! strcmp( argv[i], "-d" ) ){
            mqo_trace_flag ++;
        }else if( ! strcmp( argv[i], "-g" ) ){
            mqo_show_globals = 1;
        }else{
            mqo_tc_append( mqo_argv, mqo_vf_string( mqo_string_fs( argv[i] ) ) );
            mqo_argc ++;
        }
    };

    mqo_argv = mqo_list_fv( mqo_car( mqo_argv ) );

    mqo_list linked = mqo_thaw_tail( argv[0] );

    if( ! linked ){
        if( mqo_argv ){
            mqo_string src_path = mqo_string_fv( mqo_car( mqo_argv ) );
            mqo_file src_file = mqo_open_file( mqo_sf_string( src_path ),
                                               "r", 0600 );
            mqo_run( mqo_thaw_str( mqo_read_file( src_file, 1 << 30 ) ) );
        }
    }else while( linked ){
        mqo_run( mqo_car( linked ) );
        linked = mqo_list_fv( mqo_cdr( linked ) );
    }

    if( mqo_show_globals ){
        mqo_list globals = mqo_get_globals( );
        while( globals ){
            mqo_printsym( mqo_symbol_fv( mqo_car( mqo_pair_fv( mqo_car( globals ) ) ) ) );
            mqo_print( " -- " );
            mqo_word ct = 64; 
            mqo_show( mqo_value_type( mqo_cdr( mqo_pair_fv( mqo_car( globals ) ) ) )->name, &ct );
            mqo_newline( );
            globals = mqo_list_fv( mqo_cdr( globals ) );
        }
    };

    mqo_collect_garbage( );
    return 0;
}
