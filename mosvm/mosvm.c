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

void mqo_run( mqo_value func ){
    // TODO: Retire when process is back in.
    mqo_spawn_func( func );
    mqo_proc_loop( );
}

int main( int argc, const char** argv ){
    mqo_init_mosvm( );

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

    mqo_collect_garbage( );
    return 0;
}
