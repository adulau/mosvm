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
#include <gc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

mqo_type mqo_make_type( mqo_symbol name, mqo_type super, 
                        mqo_show_mt mt_show,
                        mqo_pair info
){
    mqo_type direct, type = MQO_ALLOC( mqo_type, 0 );

    if(! super ){
        direct = NULL;
    }else if(! super->direct ){
        direct = super;
    }else{
        direct = super->direct;
    }

    type->direct = direct;
    type->name = name;
    type->super = super;
    type->info = info;
    type->mt_show = mt_show;

    return type;
}

mqo_boolean mqo_isa( mqo_value v, mqo_type t ){
    mqo_type vt = mqo_value_type( v );

    while( vt ){
        if( vt == t ){
            return 1;
        }
        vt = vt->super;
    };

    return 0;
}

mqo_integer mqo_compare( mqo_value a, mqo_value b ){
    if( a.type > b.type ){
        return +1;
    }else if( a.type < b.type ){
        return -1;
    }else{
        if( a.data == b.data )return 0;
        if( mqo_direct_type( a ) == mqo_string_type ){
            return mqo_string_compare( mqo_string_fv( a ),
                    mqo_string_fv( b ) );
        }else{
            return a.data > b.data ? +1 : -1;
        }
    }
}
mqo_boolean mqo_eqv( mqo_value a, mqo_value b ){
    if( a.type != b.type )return 0;
    if( a.data == b.data )return 1;
    mqo_type at = mqo_value_type( a );
    if( at == mqo_vector_type ){
        return mqo_eqvv( mqo_vector_fv( a ), mqo_vector_fv( b ) );
    }else if( at == mqo_pair_type ){
        return mqo_eqvp( mqo_pair_fv( a ), mqo_pair_fv( b ) );
    }else if( at == mqo_string_type ){
        return mqo_eqvs( mqo_string_fv( a ), mqo_string_fv( b ) );
    }else{
        return 0;
    }
}
mqo_boolean mqo_equal( mqo_value a, mqo_value b ){
    if( a.type != b.type )return 0;
    if( a.data == b.data )return 1;
    mqo_type at = mqo_value_type( a );

    if( at == mqo_vector_type ){
        return mqo_equalv( mqo_vector_fv( a ), mqo_vector_fv( b ) );
    }else if( at == mqo_pair_type ){
        return mqo_equalp( mqo_pair_fv( a ), mqo_pair_fv( b ) );
    }else if( at == mqo_string_type ){
        return mqo_eqvs( mqo_string_fv( a ), mqo_string_fv( b ) );
    }else{
        return 0;
    }
}
void mqo_show_type( mqo_type type, mqo_word* ct ){
    mqo_write( "[type " );
    mqo_show_symbol( type->name, NULL );
    mqo_writech( ']' );
}
void mqo_show_boolean( int b, mqo_word* ct ){
    mqo_write( b ? "#t" : "#f" );
}
void mqo_show_integer( mqo_integer i, mqo_word* ct ){
    mqo_writeint( i );
}

MQO_DEFN_TYPE( pair );
MQO_DEFN_TYPE( symbol );
MQO_DEFN_TYPE( tree );
MQO_DEFN_TYPE( type );
MQO_DEFN_TYPE( error );
MQO_DEFN_TYPE( string );
MQO_DEFN_TYPE( guard );
MQO_DEFN_TYPE( closure );
MQO_DEFN_TYPE( vector );
MQO_DEFN_TYPE( vmstate );
MQO_DEFN_TYPE( prim );
MQO_DEFN_TYPE( instruction );
MQO_DEFN_TYPE( program );
MQO_DEFN_TYPE( process );
MQO_DEFN_TYPE( integer );
MQO_DEFN_TYPE( boolean );
MQO_DEFN_TYPE( multimethod );
MQO_DEFN_TYPE( descr );
MQO_DEFN_TYPE( tc );
MQO_DEFN_TYPE( set );
MQO_DEFN_TYPE( dict );
MQO_DEFN_TYPE2( "file-descr", file );
MQO_DEFN_TYPE( socket );
MQO_DEFN_TYPE( console );
MQO_DEFN_TYPE( listener);
MQO_DEFN_TYPE( buffer );

struct mqo_type_data mqo_quark_type_data = { NULL, NULL, NULL, NULL }; 
mqo_type mqo_quark_type = &mqo_quark_type_data; 

struct mqo_type_data mqo_void_type_data = { NULL, NULL, NULL, NULL }; 
mqo_type mqo_void_type = &mqo_void_type_data; 

mqo_type mqo_default_type = &mqo_boolean_type_data;

mqo_set mqo_globals_set( ){
    mqo_set globals = mqo_make_tree( mqo_set_key );
    MQO_ITER_TREE( mqo_lexicon, node ){
        mqo_symbol key = mqo_symbol_fv( node->data );
        if( ! mqo_is_void( key->value ) ){
            mqo_tree_insert( globals, node->data );
        }
    }
    return globals;
}
void mqo_init_memory_subsystem( ){
    mqo_symbol sym;
    
    mqo_lexicon = mqo_make_tree( mqo_symbol_key );

    MQO_BIND_TYPE( symbol, nil );
    MQO_BIND_TYPE( type, nil );
    MQO_BIND_TYPE( pair, nil );
    MQO_BIND_TYPE( error, nil );
    MQO_BIND_TYPE( process, nil );
    MQO_BIND_TYPE( string, nil );
    MQO_BIND_TYPE( guard, nil );
    MQO_BIND_TYPE( closure, nil );
    MQO_BIND_TYPE( vector, nil );
    MQO_BIND_TYPE( vmstate, nil );
    MQO_BIND_TYPE( prim, nil );
    MQO_BIND_TYPE( instruction, nil );
    MQO_BIND_TYPE( program, nil );
    MQO_BIND_TYPE( integer, nil );
    MQO_BIND_TYPE( boolean, nil );
    MQO_BIND_TYPE( multimethod, nil );
    MQO_BIND_TYPE( descr, nil );
    MQO_BIND_TYPE( tree, nil );
    
    MQO_BIND_TYPE( quark, nil );
    MQO_BIND_TYPE( void, quark );

    MQO_BIND_TYPE( tc, nil );
    MQO_BIND_TYPE( set, nil );                            
    MQO_BIND_TYPE( dict, nil );                            

    MQO_BIND_TYPE2( "file-descr", file, descr );
    MQO_BIND_TYPE( socket, descr );
    MQO_BIND_TYPE( console, descr );
    MQO_BIND_TYPE( listener, descr );
    
    MQO_BIND_TYPE( buffer, nil );                            
}
