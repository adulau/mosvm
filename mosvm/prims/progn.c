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

#include "../mosvm.h"
#include "../mosvm/prim.h"

MQO_BEGIN_PRIM( "make-program", make_program )
	REQ_INTEGER_ARG( size )
	NO_MORE_ARGS( )

	MQO_RESULT( mqo_vf_program( mqo_make_program( size ) ) );
MQO_END_PRIM( make_program )

MQO_BEGIN_PRIM( "program-length", program_length )
	REQ_PROGRAM_ARG( program )
	NO_MORE_ARGS( )
	MQO_RESULT( mqo_vf_integer( program->length ) );
MQO_END_PRIM( program_length )

MQO_BEGIN_PRIM( "set-program-code-at!", set_program_code_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	REQ_INTEGER_ARG( code )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};
	if( code >= 20 ){
		mqo_errf( mqo_es_args, "si", "code must be less than twenty",
							   index );
	};
	
	mqo_instruction instr = mqo_program_ref( program, index );
	instr->code = code;
	instr->prim = ( mqo_op_table + code )->prim; 
	MQO_NO_RESULT( );
MQO_END_PRIM( set_program_code_at )

MQO_BEGIN_PRIM( "program-code-at", program_code_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	MQO_RESULT( mqo_vf_integer( mqo_program_ref( program, index )->code ) );
MQO_END_PRIM( program_code_at )

MQO_BEGIN_PRIM( "set-program-word1-at!", set_program_word1_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	REQ_INTEGER_ARG( word1 )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	mqo_program_ref( program, index )->w.a = word1;

	MQO_NO_RESULT( );
MQO_END_PRIM( set_program_word1_at )

MQO_BEGIN_PRIM( "program-word1-at", program_word1_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	MQO_RESULT( mqo_vf_integer( mqo_program_ref( program, index )->w.a ) );
MQO_END_PRIM( program_word1_at )

MQO_BEGIN_PRIM( "set-program-word2-at!", set_program_word2_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	REQ_INTEGER_ARG( word2 )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	mqo_program_ref( program, index )->w.b = word2;

	MQO_NO_RESULT( );
MQO_END_PRIM( set_program_word2_at )

MQO_BEGIN_PRIM( "program-word2-at", program_word2_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	MQO_RESULT( mqo_vf_integer( mqo_program_ref( program, index )->w.b ) );
MQO_END_PRIM( program_word2_at )

MQO_BEGIN_PRIM( "set-program-value-at!", set_program_value_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	REQ_VALUE_ARG( value )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	mqo_program_ref( program, index )->va = value;

	MQO_NO_RESULT( );
MQO_END_PRIM( set_program_value_at )

MQO_BEGIN_PRIM( "program-value-at", program_value_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	MQO_RESULT( mqo_program_ref( program, index )->va );
MQO_END_PRIM( program_value_at )

MQO_BEGIN_PRIM( "set-program-symbol-at!", set_program_symbol_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	REQ_SYMBOL_ARG( symbol )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceeds program length",
							   index );
	};

	mqo_program_ref( program, index )->sy = symbol;

	MQO_NO_RESULT( );
MQO_END_PRIM( set_program_symbol_at )

MQO_BEGIN_PRIM( "program-symbol-at", program_symbol_at )
	REQ_PROGRAM_ARG( program )
	REQ_INTEGER_ARG( index )
	NO_MORE_ARGS( )
	
	if( index >= program->length ){
		mqo_errf( mqo_es_args, "si", "index exceesd program length",
							   index );
	};

	MQO_RESULT( mqo_vf_symbol( mqo_program_ref( program, index )->sy ) );
MQO_END_PRIM( program_symbol_at )

void mqo_bind_progn_prims( ){
    MQO_BIND_PRIM( make_program );
    MQO_BIND_PRIM( program_length );
	MQO_BIND_PRIM( program_code_at );
	MQO_BIND_PRIM( set_program_code_at );
	MQO_BIND_PRIM( program_word1_at );
	MQO_BIND_PRIM( set_program_word1_at );
	MQO_BIND_PRIM( program_word2_at );
	MQO_BIND_PRIM( set_program_word2_at );
	MQO_BIND_PRIM( program_value_at );
	MQO_BIND_PRIM( set_program_value_at );
	MQO_BIND_PRIM( program_symbol_at );
	MQO_BIND_PRIM( set_program_symbol_at );
}

