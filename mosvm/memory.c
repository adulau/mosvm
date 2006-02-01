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

mqo_tree mqo_lexicon = NULL;
// When new symbols are created from strings, a search is made of the lexicon
// for an equivalent string.

mqo_pair mqo_cons( mqo_value car, mqo_value cdr ){
    mqo_pair c = MQO_ALLOC( mqo_pair, 0 );
    mqo_set_car( c, car );
    mqo_set_cdr( c, cdr );
    return c;    
}

mqo_string mqo_string_fm( const void* s, mqo_integer sl ){
    mqo_string a = mqo_make_string( sl );
    memcpy( a->data, s, sl );
    a->data[sl+1] = 0;
    return a;
}
mqo_string mqo_string_fs( const char* s ){
    return mqo_string_fm( (const void*)s, strlen( s ) );
}

mqo_value mqo_symbol_key( mqo_value item ){
    return mqo_vf_string( mqo_symbol_fv( item )->string );
}

mqo_symbol mqo_symbol_fm( const void* s, mqo_integer sl ){
    mqo_pair lx;
    mqo_symbol sym;
    mqo_string str;
    mqo_node node; 

    str = mqo_string_fm( s, sl );
    
    node = mqo_tree_lookup( mqo_lexicon, mqo_vf_string( str ) );
    if( node ){ 
        GC_free( str );
        return mqo_symbol_fv( node->data ); 
    }else{
        sym = MQO_ALLOC( mqo_symbol, 0 );
        sym->string = str;
        sym->value = mqo_make_void();
        mqo_tree_insert( mqo_lexicon, mqo_vf_symbol( sym ) );
        return sym;
    }
}

mqo_symbol mqo_symbol_fs( const char* s ){
    return mqo_symbol_fm( s, strlen( s ) );
}

void mqo_tc_append( mqo_pair tc, mqo_value v ){
    mqo_pair it = mqo_cons( v, mqo_vf_empty() );
    
    mqo_pair pv = mqo_pair_fv( mqo_cdr( tc ) );
    
    if( pv ){
	mqo_set_cdr( pv, mqo_vf_pair( it ) );
    }else{
	mqo_set_car( tc, mqo_vf_pair( it ) );
    }
    
    mqo_set_cdr( tc, mqo_vf_pair( it ) );
}

mqo_pair mqo_list_ref( mqo_pair p, mqo_integer offset ){
    while( p && offset ){
        offset--; 
        p = mqo_pair_fv( mqo_cdr( p ) );
    }
    return p;
}

mqo_vector mqo_make_vector( mqo_integer length ){
    size_t tail = sizeof( mqo_value ) * length;
    mqo_vector v = MQO_ALLOC( mqo_vector, tail );

    v->length = length;
    memset( v->data, 0,  tail );
    return v;
}
mqo_program mqo_make_program( mqo_integer length ){
    size_t tail = sizeof( struct mqo_instruction_data ) * length;
    mqo_program v = MQO_ALLOC( mqo_program, tail );

    v->length = length;
    memset( v->inst, 0, tail );
    return v;
}
mqo_instruction mqo_program_ref( mqo_program program, mqo_integer index ){
    assert( program->length > index );
    return program->inst + index;
}

mqo_closure mqo_make_closure( mqo_program cp, mqo_instruction ip, mqo_pair ep ){
    mqo_closure c = MQO_ALLOC( mqo_closure, 0 );
    
    c->cp = cp;
    c->ip = ip;
    c->ep = ep;

    return c;
}
mqo_error mqo_make_error( mqo_symbol key, mqo_pair info ){
    mqo_error e = MQO_ALLOC( mqo_error, 0 );
    mqo_vmstate s = mqo_make_vmstate( );

    e->key = key;
    e->info = info;
    e->state = s;

    s->cp = MQO_CP;
    s->ip = MQO_IP;
    s->rv = mqo_copy_vector( MQO_RV, MQO_RI );
    s->sv = mqo_copy_vector( MQO_SV, MQO_SI );
    s->ri = MQO_RI;
    s->si = MQO_SI;
    s->ep = MQO_EP;
    s->gp = MQO_GP;

    return e;
}
mqo_guard mqo_make_guard( 
    mqo_value fn, mqo_integer ri, mqo_integer si, 
    mqo_program cp,  mqo_instruction ip, mqo_pair ep
){
    mqo_guard e = MQO_ALLOC( mqo_guard, 0 );

    e->fn = fn;
    e->ri = ri;
    e->si = si;
    e->cp = cp;
    e->ip = ip;
    e->ep = ep;

    return e;
}
mqo_vmstate mqo_make_vmstate( ){
    mqo_vmstate e = MQO_ALLOC( mqo_vmstate, 0 );

    return e;
}
mqo_vector mqo_copy_vector( mqo_vector vo, mqo_integer ln ){
    mqo_vector vn = mqo_make_vector( ln );
    while( ln-- ){
        mqo_vector_put( vn, ln, mqo_vector_get( vo, ln ) );
    }
    return vn;
}
mqo_prim mqo_make_prim( const char *name, mqo_prim_fn fn ){
    mqo_prim p = MQO_ALLOC( mqo_prim, 0 );
    p->name = mqo_string_fs( name );
    p->fn = fn;
    return p;
}
mqo_process mqo_make_process( ){
    mqo_process p = MQO_ALLOC( mqo_process, 0 );
    mqo_vmstate s = mqo_make_vmstate( );
    p->status = mqo_ps_suspended;
    p->state = s;
    s->rv = mqo_make_vector( MQO_STACK_SZ );
    s->sv = mqo_make_vector( MQO_STACK_SZ );
    return p;
}
mqo_string mqo_make_string( mqo_integer length ){
    mqo_string s = MQO_ALLOC( mqo_string, length + 1 );
    s->length = length;
    return s;
}
mqo_type mqo_make_type( mqo_type direct, mqo_symbol name, mqo_type super, mqo_pair info ){
    mqo_type type = MQO_ALLOC( mqo_type, 0 );
    type->direct = direct;
    type->name = name;
    type->super = super;
    type->info = info;
    return type;
}

mqo_multimethod mqo_make_multimethod( 
   mqo_value signature, mqo_value func, mqo_value next
){
    mqo_multimethod mt = MQO_ALLOC( mqo_multimethod, 0 );
    mt->signature = signature;
    mt->func = func;
    mt->next = next;
    return mt;
}
void mqo_descr_finalizer( void* ptr, void* cd ){
    if( mqo_trace_vm ){
        printf( "Finalizing descriptor " );
        mqo_show_descr( (mqo_descr)ptr );
        printf( "..\n" );
    }
    if( ! ((mqo_descr)ptr)->closed )close( ((mqo_descr)ptr)->fd );
}
mqo_descr mqo_make_descr( mqo_string path, int fd, mqo_byte type ){
    mqo_descr f = MQO_ALLOC( mqo_descr, 0 );
    f->name = path;
    f->fd = fd;
    f->result = mqo_make_void( );
    GC_register_finalizer( f, mqo_descr_finalizer, NULL, NULL, NULL );
    return f;
}
mqo_file mqo_make_file( mqo_string path, int fd ){
    return mqo_make_descr( path, fd, MQO_FILE );
}
mqo_socket mqo_make_socket( mqo_string path, int fd ){
    return mqo_make_descr( path, fd, MQO_SOCKET );
}
mqo_listener mqo_make_listener( mqo_string path, int fd ){
    return mqo_make_descr( path, fd, MQO_LISTENER );
}
mqo_console mqo_make_console( mqo_string path ){
    return mqo_make_descr( path, 0, MQO_CONSOLE );
}

mqo_tc mqo_make_tc( ){
    return (mqo_tc)mqo_cons( mqo_vf_empty(), mqo_vf_empty() );
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
MQO_DEFN_TYPE( file );
MQO_DEFN_TYPE( socket );
MQO_DEFN_TYPE( console );
MQO_DEFN_TYPE( listener);

struct mqo_type_data mqo_atom_type_data = { NULL, NULL, NULL, NULL }; 
mqo_type mqo_atom_type = &mqo_atom_type_data; 

struct mqo_type_data mqo_void_type_data = { NULL, NULL, NULL, NULL }; 
mqo_type mqo_void_type = &mqo_void_type_data; 

mqo_type mqo_default_type = &mqo_boolean_type_data;

mqo_integer mqo_string_compare( mqo_string a, mqo_string b ){
    //This will result in dictionary-style ordering of strings,
    //with case sensitivity.
    //
    //NOTE: Ideally, we would also use a string hash here to
    //      give us a second form of equality testing prior
    //      to degenerating into memcmp, but there's a point
    //      where performance optimizations must give way.

    mqo_integer al = mqo_string_length( a );
    mqo_integer bl = mqo_string_length( b );
    mqo_integer d = memcmp( mqo_sf_string( a ), 
                            mqo_sf_string( b ),
                            al < bl ? al : bl );

    return d ? d : ( al - bl );
}

mqo_integer mqo_compare( mqo_value a, mqo_value b ){
    mqo_integer d = (mqo_integer)( a.type - b.type );
    if( d )return d;
    if( a.data == b.data )return 0;

    if( mqo_direct_type( a ) == mqo_string_type ){
        return mqo_string_compare( mqo_string_fv( a ),
                                   mqo_string_fv( b ) );
    }else{
        return a.data - b.data;
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

mqo_boolean mqo_eqvv( mqo_vector a, mqo_vector b ){
    mqo_integer i;
    mqo_integer l = mqo_vector_length( a );
    if( l != mqo_vector_length( b ) )return 0;
    for( i = 0; i < l; i++ ){
        if( ! mqo_eq( mqo_vector_get( a, i ),
                      mqo_vector_get( b, i ) ) )return 0;
    }
    return 1;
}

mqo_boolean mqo_eqvp( mqo_pair a, mqo_pair b ){
    mqo_value av, bv;

    for(;;){
        if( !a )return !b;
        if( !b )return 0;

        if( !mqo_eq( mqo_car( a ), mqo_car ( b ) ) )return 0;
        av = mqo_cdr( a );
        bv = mqo_cdr( b );

        if( av.type != bv.type )return 0;
        if( av.type != mqo_pair_type )return av.data == bv.data;

        a = mqo_pair_fv( av );
        b = mqo_pair_fv( bv );
    }
    // We surrender! It's equal! It's equal!
    return 1;
}

mqo_boolean mqo_eqvs( mqo_string a, mqo_string b ){
    mqo_integer l = mqo_string_length( a );
    if( l != mqo_string_length( b ) )return 0;
    return ! memcmp( a->data, b->data, l );
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

mqo_boolean mqo_equalv( mqo_vector a, mqo_vector b ){
    mqo_integer i;
    mqo_integer l = mqo_vector_length( a );
    if( l != mqo_vector_length( b ) )return 0;
    for( i = 0; i < l; i++ ){
        if( ! mqo_equal( mqo_vector_get( a, i ),
                         mqo_vector_get( b, i ) ) )return 0;
    }
    return 1;
}

mqo_boolean mqo_equalp( mqo_pair a, mqo_pair b ){
    mqo_value av, bv;

    for(;;){
        if( !a )return !b;
        if( !b )return 0;

        if( !mqo_equal( mqo_car( a ), mqo_car ( b ) ) )return 0;
        av = mqo_cdr( a );
        bv = mqo_cdr( b );

        if( av.type != bv.type )return 0;
        if( av.type != mqo_pair_type )return mqo_equal( av, bv );

        a = mqo_pair_fv( av );
        b = mqo_pair_fv( bv );
    }
    // We surrender! It's equal! It's equal!
    return 1;
}

mqo_pair mqo_last_pair( mqo_pair p ){
    //TODO: Does not handle circular lists.
    if( ! p ){ goto done; }
    for(;;){
        mqo_value v = mqo_cdr( p );
        if(( ! mqo_is_pair( v ) )|| mqo_is_empty( v )){
            goto done;
        }else{
            p = mqo_pair_fv( v );
        };
    }
done:
    return p;
}

mqo_pair mqo_req_list( mqo_value v, const char* s ){
    mqo_pair pair = mqo_req_pair( v, s );
    if( pair )return pair;
    mqo_errf( mqo_es_args, "ss", "expected non-empty list for", s ); 
}

mqo_value mqo_set_key( mqo_value item ){ return item; }
mqo_value mqo_dict_key( mqo_value item ){ 
    return mqo_car( mqo_pair_fv( item ) ); 
}

void mqo_init_memory_subsystem( ){
    mqo_symbol sym;
    
    mqo_lexicon = mqo_make_tree( mqo_symbol_key );

    MQO_BIND_TYPE( symbol, NULL, NULL );
    MQO_BIND_TYPE( type, NULL, NULL );
    MQO_BIND_TYPE( pair, NULL, NULL );
    MQO_BIND_TYPE( error, NULL, NULL );
    MQO_BIND_TYPE( process, NULL, NULL );
    MQO_BIND_TYPE( string, NULL, NULL );
    MQO_BIND_TYPE( guard, NULL, NULL );
    MQO_BIND_TYPE( closure, NULL, NULL );
    MQO_BIND_TYPE( vector, NULL, NULL );
    MQO_BIND_TYPE( vmstate, NULL, NULL );
    MQO_BIND_TYPE( prim, NULL, NULL );
    MQO_BIND_TYPE( instruction , NULL, NULL );
    MQO_BIND_TYPE( program, NULL, NULL );
    MQO_BIND_TYPE( integer, NULL, NULL );
    MQO_BIND_TYPE( boolean, NULL, NULL );
    MQO_BIND_TYPE( multimethod, NULL, NULL );
    MQO_BIND_TYPE( descr, NULL, NULL );
    MQO_BIND_TYPE( tree, NULL, NULL );
    
    MQO_BIND_TYPE( atom, NULL, NULL );
    MQO_BIND_TYPE( void, mqo_atom_type, mqo_atom_type );

    MQO_BIND_TYPE( tc, NULL, NULL );
    MQO_BIND_TYPE( set, NULL, NULL );                            
    MQO_BIND_TYPE( dict, NULL, NULL );                            

    MQO_BIND_TYPE( file, mqo_descr_type, mqo_descr_type );
    MQO_BIND_TYPE( socket, mqo_descr_type, mqo_descr_type );
    MQO_BIND_TYPE( console, mqo_descr_type, mqo_descr_type );
    MQO_BIND_TYPE( listener, mqo_descr_type, mqo_descr_type );
}
