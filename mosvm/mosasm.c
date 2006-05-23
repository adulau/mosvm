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

int main( int argc, const char* argv[] ){
    if( argc != 3 ){
        mqo_print( 
"mosasm src-file dst-file\n\n" 
"Used to construct Mosquito Object Package files from Mosquito Assembler "
"files.  Primarily employed by the Mosquito Lisp compiler in seed mode, and "
"the Mosquito Virtual Machine unit tests.\n"
        );
        return 1;
    }else{
        mqo_init_mosvm();
        mqo_string src = mqo_read_file( argv[1] );
        mqo_boolean ok = 1;
        mqo_pair   dta = mqo_parse_document( mqo_sf_string( src ), &ok );
        if(! ok ){
            mqo_print( "PARSE: ");
            mqo_print( mqo_parse_errmsg );
            mqo_newline();
            return 2;
        }
        mqo_procedure proc = mqo_assemble( dta );
        mqo_write_file( argv[2], mqo_freeze( mqo_vf_procedure( proc ) ) );
        return 0;
    }
}
