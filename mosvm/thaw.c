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
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include "mosvm.h"

#define REPORT_ERROR( s ){ error = "thaw: " s "."; goto yield; }
#define CHECK_UNDERFLOW( x, s ) if( len < ( ofs + (x) ) ) REPORT_ERROR( "data underflow while trying to read " s );
#define CHECK_REF( x, s ) if( ct <= (x) )REPORT_ERROR( "record " s " reference exceeds record count" );

mqo_pair mqo_thaw_memory( const char* data, size_t len ){
    uint16_t i, ct, ix, result_ix = 0;
    size_t ofs, ln;
    mqo_value* codex = NULL;
    mqo_value* vp = NULL;
    mqo_value result;
    mqo_pair p;
    mqo_program g;
    mqo_word car;
    mqo_word cdr;
    const char* error = NULL;

    mqo_byte read_byte( ){ return (mqo_byte)data[ofs++]; }
    mqo_word read_word( ){ return (read_byte() << 8) + read_byte(); }
    mqo_long read_long( ){ return (read_word() << 16) + read_word( ); }
    
    ofs = 0;
    
    // Read the record count..
    CHECK_UNDERFLOW( 2, "record count" );
    ct = read_word( );

    // Read the result index..
    CHECK_UNDERFLOW( 2, "result index" );
    result_ix = read_word( );

    // Initialize the codex..
    size_t sz = sizeof( mqo_value ) * ct;

    codex = (mqo_value*)GC_malloc( sz );
    if( codex == NULL )REPORT_ERROR( "out of memory while allocating"
				     " record table" )
    memset( codex, 0, sz );
     
    // For each record, determine type and allocate.. Init if non-pair..
    for( ix = 0; ix < ct; ix ++ ){
	CHECK_UNDERFLOW( 1, "a record type" );

	switch( read_byte() ){
	    case MQO_THAW_NIL:
		codex[ ix ] = mqo_vf_empty();
		break;
	    case MQO_THAW_T:	
		codex[ ix ] = mqo_vf_true();
		break;
	    case MQO_THAW_F:
		codex[ ix ] = mqo_vf_false();
		break;
	    case MQO_THAW_POSINT:
		CHECK_UNDERFLOW( 4, "an integer's value" );
		
		codex[ ix ] = mqo_vf_integer( read_long( ) );
    		break;
	    case MQO_THAW_NEGINT:
		CHECK_UNDERFLOW( 4, "an integer's value" );
		
		codex[ ix ] = mqo_vf_integer( - read_long( ) );
		break;
	    case MQO_THAW_STRING:
		CHECK_UNDERFLOW( 2, "a string's length" );
		ln = read_word( );
		
		CHECK_UNDERFLOW( ln, "a string's content" );
		codex[ ix ] = mqo_vf_string( mqo_string_fm( data + ofs, ln ) );
		
		ofs += ln;
		break;
	    case MQO_THAW_SYMBOL:
		CHECK_UNDERFLOW( 2, "a symbol's length" );
		ln = read_word( );
		
		CHECK_UNDERFLOW( ln, "a symbol's content" );
		codex[ ix ] = mqo_vf_symbol( mqo_symbol_fm( data + ofs, ln ) );
		
		ofs += ln;
		break;
	    case MQO_THAW_PAIR:
		CHECK_UNDERFLOW( 2, "a pair's left value" ); 
                ofs += 2;		
		
                CHECK_UNDERFLOW( 2, "a pair's right value" ); 
                ofs += 2;
		
		codex[ ix ] = mqo_vf_pair( 
                    mqo_cons( mqo_vf_empty(), mqo_vf_empty() ) 
                );

		break;
	    case MQO_THAW_VECTOR:
		CHECK_UNDERFLOW( 2, "a vector's length" ); 
                ln = read_word( );
		CHECK_UNDERFLOW( ln << 1, "a vector's content" ); 
                ofs += ln << 1;
		
		codex[ ix ] = mqo_vf_vector( mqo_make_vector( ln ) );
		break;
            case MQO_THAW_PROGRAM:
                CHECK_UNDERFLOW( 2, "a program's length" );
                ln = read_word( );
                g = mqo_make_program( ln );
                codex[ ix ] = mqo_vf_program( g );
                for( i = 0; i < g->length; i ++ ){
                    ln = read_byte( );
                    struct mqo_op_row* row = mqo_op_table + ln;
                    if( row->use_sy ){ 
                        ofs += 2;
                    }else if( row->use_va ){ 
                        ofs += 2;
                    }else if( row->use_w1 ){ 
                        ofs += 2;
                        if( row->use_w2 ){ 
                            ofs += 2;
                        };
                    };
                }
                    
                break;
	    default:
		REPORT_ERROR( "unrecognized record type encountered" );
	}
    }
    ofs = 4;
    
    // For each record, if the record is a pair, bind pointers to the contained values.
    for( ix = 0; ix < ct; ix ++ ){
	switch( read_byte() ){
	    case MQO_THAW_POSINT:
	    case MQO_THAW_NEGINT:
		ofs += 4; 
		break;
	    case MQO_THAW_STRING:
	    case MQO_THAW_SYMBOL:
		ofs += read_word( ); 
		break;
	    case MQO_THAW_PAIR:
		p = mqo_pair_fv( codex[ ix ] );
		
		car = read_word( );
		cdr = read_word( );
		
		CHECK_REF( car, "car" );
		CHECK_REF( cdr, "cdr" );
		
		mqo_set_car( p, codex[ car ] );
		mqo_set_cdr( p, codex[ cdr ] );
		break;
	    case MQO_THAW_VECTOR:
		ln = read_word( );
		vp = mqo_vector_ref( mqo_vector_fv( codex[ ix ] ), 0 );

                while( ln-- ){
                    car = read_word( );
		    CHECK_REF( car, "item" );
                    *( vp++ ) = codex[ car ];
                }

		break;
            case MQO_THAW_PROGRAM:
                ofs += 2; 
                g = mqo_program_fv( codex[ ix ] );
                for( i = 0; i < g->length; i ++ ){
                    mqo_instruction gi = g->inst + i;
                    gi->code = read_byte( );
                    struct mqo_op_row* row = mqo_op_table + gi->code; 

                    if( row->use_sy ){ 
                        car = read_word( );
                        CHECK_REF( car, "instruction" );
                        gi->sy = mqo_symbol_fv( codex[ car ] );
                    }else if( row->use_va ){ 
                        car = read_word( );
                        CHECK_REF( car, "instruction" );
                        gi->va = codex[ car ];
                    }else if( row->use_w1 ){ 
                        gi->w.a = read_word( );
                        if( row->use_w2 ){ 
                           gi->w.b = read_word( );
                        };
                    };
                    gi->prim = row->prim;
                }
                    
                break;
	};
    }
    
yield:
    if( codex ){
	result = codex[ result_ix ];   
	GC_free( codex );    
    }
    
    if( error )return mqo_cons( mqo_vf_false(), mqo_vf_string( mqo_string_fm( error, strlen( error ) ) ) );

    return mqo_cons( mqo_vf_true(), result);	
}

/* Original inspiration for mqo_thaw_frag taken from public domain code
 * by Luiz Henrique de Figueiredo <lhf@tecgraf.puc-rio.br>
 */

const char* mqo_frag_tag = "mvf2";
const int mqo_frag_taglen = 4;

#define cannot(x) \
    mqo_errf( \
        mqo_es_vm, "ss", "cannot " x "-", strerror(errno) \
    );

#define TAIL_JUMP( fil, ofs ) \
    *inset -= ofs; \
    if( fseek( fil, *inset, SEEK_END ) != 0 )cannot( "seek" );

#define TAIL_READ( fil, ptr, cnt ) \
    TAIL_JUMP( fil, cnt ); \
    if( fread( ptr, cnt, 1, fil ) != 1 )cannot( "read" ) 

#define TAIL_READ_VAR( fil, var ) \
    TAIL_READ( fil, &var, sizeof( var ) );

#define TAIL_READ_SHORT( fil, var ) \
    TAIL_READ_VAR( fil, var ); var = ntohs( var );

mqo_value mqo_thaw_frag( FILE *f, mqo_integer *inset ) {
    char* code;
    mqo_word code_len; 

    TAIL_READ_SHORT( f, code_len );
   
    code = GC_malloc( code_len + 1 );
    
    TAIL_READ( f, code, code_len );
    code[code_len] = 0;

    mqo_pair p = mqo_thaw_memory( code, code_len );
    if( ! mqo_is_true( mqo_car( p ) ) ){
        cannot( "thaw" );
    }
    
    GC_free( code );
    return mqo_cdr( p );
}

mqo_pair mqo_thaw_tail( const char *name ) {
    char sig[mqo_frag_taglen];
    mqo_word i, count;
    mqo_integer iinset = 0;
    mqo_integer *inset = &iinset;
    mqo_pair p = NULL;
    mqo_value v;

    FILE *f=fopen(name,"rb");

    if (f==NULL){
        cannot("open");
    };

    for(;;){
        TAIL_READ( f, sig, mqo_frag_taglen );
        if (memcmp(sig,mqo_frag_tag,mqo_frag_taglen)!=0) return p;
        v = mqo_thaw_frag( f, inset );
        p = mqo_cons( v, mqo_vf_pair( p ) ); 
    }

    fclose(f);

    return p;
}
