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
#include <stdio.h>

void _mqo_show( mqo_value v, mqo_word* ct );

void mqo_show_cstring( const char* st ){
    fputs( st, stdout );
}

void mqo_newline( ){
    putchar( '\n' );
}

void mqo_space( ){
    putchar( ' ' );
}

void mqo_show_integer( mqo_integer i ){
    //TODO: Replace.
    printf( "%i", i );
};

void _mqo_show_vector( mqo_vector v, mqo_word* ct ){
    mqo_integer ln = mqo_vector_length( v );
    mqo_integer ix = 0;

    printf( "#%i(", ln );
    
    for( ix = 0; ix < ln; ix ++ ){
        if( ct ){
	    if( ! *ct ){
	        mqo_show_cstring( " ..." ); 
                goto done;
	    }
	
            (*ct)--;
        }

        mqo_show_cstring( " " );
        _mqo_show( mqo_vector_get( v, ix), ct );
    }
    
done:
    mqo_show_cstring( " )" );
} 

void _mqo_show_tree( mqo_tree t, mqo_word* ct ){
    mqo_node n = mqo_first_node( t );
    int f = 0;

    mqo_show_cstring( "{" );
    for(;;){
        n = mqo_next_node( n );
        if( !n ) goto done;
        
        if( f ){
            mqo_show_cstring( ", " );
        }else{
            f = 1;
            mqo_show_cstring( " " );
        }

        if( ct ){
            if( ! *ct ){
                mqo_show_cstring( "..." );
                goto done;
            }

            (*ct)--;
        }

        _mqo_show( n->data, ct );
    }
done:
    mqo_show_cstring( " }" );
}

void mqo_show_tree( mqo_tree t, mqo_word ct ){
    _mqo_show_tree( t, ct ? &ct : NULL );
}

#define _mqo_show_dict _mqo_show_tree
#define _mqo_show_set  _mqo_show_tree    

void mqo_show_addr( mqo_integer a ){
    printf( "%x", a );
}

void mqo_show_closure( mqo_closure c ){
    mqo_show_cstring( "<func " );
    if( c->name ){
        mqo_show_symbol( c->name );
        mqo_show_cstring( "/" );
    };
    mqo_show_addr( (mqo_integer)c );
    mqo_show_cstring( ">" );
}

void mqo_show_prim( mqo_prim p ){
    mqo_show_cstring( "<prim " );
    mqo_show_string( p->name );
    mqo_show_cstring( ">" );
}

void _mqo_show_pair_contents( mqo_pair p, mqo_word* ct ){
    int show_item( mqo_value v ){
        if( ct ){
            if( ! *ct ){
                mqo_show_cstring( "..." );
                p = NULL;
                return 1;
            }

            (*ct)--;
        }
        
        _mqo_show( v, ct );	
        return 0;
    }

    while( p ){
        mqo_value car = mqo_car( p );
        mqo_value cdr = mqo_cdr( p );
        if( show_item( car ) )return;

        if( mqo_is_pair( cdr ) ){
            p = mqo_pair_fv( cdr );
            if( p )mqo_space( );
        }else{
            mqo_show_cstring( " . " );
            if( show_item( cdr ) )return; 
            p = NULL;
        };
    }
}
void _mqo_show_pair( mqo_pair p, mqo_word* ct ){
    mqo_show_cstring( "(" );
    _mqo_show_pair_contents( p, ct );
    mqo_show_cstring( ")" );
}
void _mqo_show_tc( mqo_tc t, mqo_word* ct ){
    mqo_show_cstring( "<tc>" );
    return;
    if(mqo_is_empty( mqo_car( t ) )){
        mqo_show_cstring("(tc)");
    }else{
        mqo_show_cstring( "(tc " );
        if( ct && (! *ct ) ){
            mqo_show_cstring( "..." );
        }else{
            _mqo_show_pair_contents( mqo_pair_fv( mqo_car( t ) ), ct );
        }
        mqo_show_cstring( ")" );
    }
}
void mqo_show_vector( mqo_vector p, mqo_word ct ){
    _mqo_show_vector( p, ct ? &ct : (mqo_word*)NULL );
}
void mqo_show_pair( mqo_pair p, mqo_word ct ){
    _mqo_show_pair( p, ct ? &ct : (mqo_word*)NULL );
}
void mqo_show_string( mqo_string a ){
    mqo_show_cstring( (char*)a->data );    
}
void mqo_show_symbol( mqo_symbol s ){
    (!s) ? printf( "<<NULL>>" ) : mqo_show_string( s->string );
}
void mqo_show_boolean( int b ){
    mqo_show_cstring( b ? "#t" : "#f" );
}
void _mqo_show_error( mqo_error e, mqo_word* ct ){
    mqo_show_cstring( "<error " );
    mqo_show_symbol( e->key );
    MQO_FOREACH( e->info, pair ){
        if( ct ){
            if( *ct ){ (*ct)--; }else{
                mqo_show_cstring( "..." );
                goto done;
            }
        }
        mqo_space( );
        _mqo_show( mqo_car( pair ), ct );
    }
done:
    mqo_show_cstring( ">" );
}
void mqo_show_error( mqo_error e, mqo_word ct ){
    _mqo_show_error( e, ct ? &ct : (mqo_word*)NULL );
}
void _mqo_show_instruction( mqo_instruction i, mqo_word* ct ){
    struct mqo_op_row* op = mqo_op_table + i->code;

    mqo_show_cstring( "(" );
    mqo_show_cstring( op->name );

    if( op->use_sy ){
        mqo_space( );
        mqo_show_symbol( i->sy );
    }else if( op->use_va ){
        mqo_space( );
        _mqo_show( i->va, ct );
    }else if( op->use_w1 ){
        mqo_space( );
        mqo_show_integer( i->w.a );
        if( op->use_w2 ){
            mqo_space( );
            mqo_show_integer( i->w.b );
        }
    }
    mqo_show_cstring( ")" );
}
void mqo_show_instruction( mqo_instruction i, mqo_word ct ){
    _mqo_show_instruction( i, ct ? &ct : (mqo_word*)NULL );
}
void mqo_show_descr( mqo_descr f ){
    mqo_show_cstring( f->closed ? "<closed descr " : "<open descr " );
    mqo_show_string( f->name );
    mqo_show_cstring( ">" );
}
void _mqo_show_program( mqo_program p, mqo_word* ct ){
	mqo_show_cstring( "<program ...>" ); return;
    mqo_show_cstring( "<program" );
    for( mqo_integer i = 0; i < p->length; i ++ ){
        mqo_space( );
        if( ct ){
            if( ! *ct ){
                mqo_show_cstring( "..." );
                goto done;
            }
            (*ct)--;
        }
        mqo_show_instruction( p->inst + i, 3 );
    }
done:
    mqo_show_cstring( ">" );
}
void mqo_show_program( mqo_program p, mqo_word ct ){
    _mqo_show_program( p, &ct );
}
void mqo_show_atom( mqo_value v ){
    mqo_show_cstring( "<<" );
    mqo_show_symbol( mqo_value_type( v )->name );
    mqo_show_cstring( ">>" );
}
void mqo_show_type( mqo_type type ){
    mqo_show_cstring( "<" );
    mqo_show_symbol( type->name );
    mqo_show_cstring( ">" );
}
void mqo_show_process( mqo_process p ){
    mqo_show_cstring( "<" );
    mqo_show_symbol( p->status );
    mqo_show_cstring( " process " );
    mqo_show_integer( (mqo_integer)p );
    mqo_show_cstring( ">" );
}
void _mqo_show( mqo_value v, mqo_word* ct ){
    if( mqo_is_string( v ) ){
        mqo_show_string( mqo_string_fv( v ) );
    }else if( mqo_is_symbol( v ) ){
        mqo_show_symbol( mqo_symbol_fv( v ) );
    }else if( mqo_is_prim( v ) ){
        mqo_show_prim( mqo_prim_fv( v ) );
    }else if( mqo_is_integer( v ) ){
        mqo_show_integer( mqo_integer_fv( v ) );
    }else if( mqo_is_pair( v ) ){
        _mqo_show_pair( mqo_pair_fv( v ), ct );
    }else if( mqo_is_tc( v ) ){
        _mqo_show_tc( mqo_tc_fv( v ), ct );
    }else if( mqo_is_error( v ) ){
        _mqo_show_error( mqo_error_fv( v ), ct );
    }else if( mqo_is_vector( v ) ){
        _mqo_show_vector( mqo_vector_fv( v ), ct );
    }else if( mqo_is_tree( v ) ){
        _mqo_show_tree( mqo_tree_fv( v ), ct );
    }else if( mqo_is_dict( v ) ){
        _mqo_show_dict( mqo_dict_fv( v ), ct );
    }else if( mqo_is_set( v ) ){
        _mqo_show_set( mqo_set_fv( v ), ct );
    }else if( mqo_is_boolean( v ) ){
        mqo_show_boolean( mqo_boolean_fv( v ) );
    }else if( mqo_is_program( v ) ){
        _mqo_show_program( mqo_program_fv( v ), ct );
    }else if( mqo_is_closure( v ) ){
        mqo_show_closure( mqo_closure_fv( v ) );
    }else if( mqo_is_descr( v ) ){
        mqo_show_descr( mqo_descr_fv( v ) );
    }else if( mqo_is_instruction( v ) ){
        _mqo_show_instruction( mqo_instruction_fv( v ), ct );
    }else if( mqo_is_type( v ) ){
        mqo_show_type( mqo_type_fv( v ) );
    }else if( mqo_is_process( v ) ){
        mqo_show_process( mqo_process_fv( v ) );
    }else if( mqo_isa( v, mqo_atom_type ) ){
        mqo_show_atom( v );
    }else{
        mqo_show_cstring( "[a " );
        mqo_show_symbol( mqo_value_type( v )->name );
        mqo_show_cstring( "]" );
    };
}
void mqo_show( mqo_value v, mqo_word ct ){
    _mqo_show( v, ct ? &ct : (mqo_word*)NULL );
}
