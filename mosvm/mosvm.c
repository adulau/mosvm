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
#include <windows.h>
#else
#include <signal.h>

//TODO: Add (disable-sigint) so the drone can block this.
void mqo_handle_sigint( int sig ){
    mqo_string s = mqo_make_string( 128 );
    mqo_string_append_newline( s );
    mqo_string_append_cs( s, "Interrupted by user." );
    mqo_string_append_newline( s );
    mqo_format_context( s, mqo_frame_context( MQO_CP ) );
    mqo_string_append_newline( s );
    mqo_printstr( s );
    exit(909);
}
#endif

void mqo_run( mqo_value func, mqo_list rest ){
    // TODO: Retire when process is back in.
    mqo_process p = mqo_spawn_call( mqo_cons( func, mqo_vf_list( rest ) ) );
#ifdef _WIN32
    // TODO: win32 does not have a default stdio.
    mqo_set_process_output( p, (mqo_object) mqo_make_channel( ) );
    mqo_set_process_input( p, (mqo_object) mqo_make_channel( ) );
#else
    mqo_set_process_output( p, (mqo_object) mqo_stream_input( mqo_stdio ) );
    mqo_set_process_input( p, (mqo_object) mqo_stream_output( mqo_stdio ) );
#endif
    mqo_proc_loop( );
}

int main( int argc, const char** argv ){
    mqo_init_mosvm( );
    mqo_list linked;
    mqo_string mosvm;

#ifdef _WIN32
    char name[MAX_PATH];
    if (GetModuleFileName(NULL,name,sizeof(name))!=0){
        mosvm = mqo_string_fs( name );
    }
#else
    signal( SIGINT, mqo_handle_sigint );
    // SIGPIPE is the devil; mosvm's write operations check for errors.
    signal( SIGPIPE, SIG_IGN );
    mosvm = mqo_string_fs( argv[0] );
    if( ! mqo_file_exists( mosvm ) ) mosvm = mqo_locate_util( mosvm );
#endif
    if( ! mosvm ){
        mqo_errf(
            mqo_es_vm, "s", "cannot identify the location of mosvm"
        );
        return EXIT_FAILURE;
    }

    linked = mqo_thaw_tail( mqo_sf_string( mosvm ) );
    mqo_root_obj( (mqo_object) linked );

    mqo_argv = mqo_make_tc( );
    mqo_argc = 0;
    int i, mqo_show_globals = 0;
    for( i = 1; i < argc; i ++ ){
        if( ! strcmp( argv[i], "-d" ) ){
            mqo_trace_flag ++;
        }else if( ! strcmp( argv[i], "-x" ) ){
            mqo_abort_on_error = 1;
        }else if( ! strcmp( argv[i], "-g" ) ){
            mqo_show_globals = 1;
        }else{
            mqo_tc_append( mqo_argv, mqo_vf_string( mqo_string_fs( argv[i] ) ) );
            mqo_argc ++;
        }
    };

    mqo_argv = mqo_list_fv( mqo_car( mqo_argv ) );
    mqo_root_obj( (mqo_object) mqo_argv );

    if( ! linked ){
        if( mqo_argv ){
            mqo_string src_path = mqo_string_fv( mqo_car( mqo_argv ) );
            mqo_file src_file = mqo_open_file( mqo_sf_string( src_path ),
                                               "r", 0600 );
            mqo_run( mqo_thaw_str( mqo_read_file( src_file, 1 << 30 ) ), NULL );
        }
    }else while( linked ){
        mqo_run( mqo_car( linked ), NULL );
        linked = mqo_list_fv( mqo_cdr( linked ) );
    }
    
    mqo_symbol mqo_sym_main = mqo_symbol_fs( "main" );

    if( mqo_has_global( mqo_sym_main ) ){
        mqo_run( mqo_get_global( mqo_sym_main ), mqo_argv );
    };

    if( mqo_show_globals ){
        mqo_list globals = mqo_get_globals( );
        while( globals ){
            mqo_show( mqo_car( mqo_pair_fv( mqo_car( globals ) ) ) );
            mqo_print( " -- " );
            mqo_show( mqo_value_type( mqo_cdr( mqo_pair_fv( mqo_car( globals ) ) ) )->name );
            mqo_newline( );
            globals = mqo_list_fv( mqo_cdr( globals ) );
        };
    };

    return 0;
}
