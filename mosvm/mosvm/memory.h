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

#ifndef MQO_MEMORY_H
#define MQO_MEMORY_H 1

#include <gc.h>
#include "integer.h"

//Q: What is the difference between using _fv and _req_ functions for
//   conversion? They both raise errors..
//
//A: Assertions will be turned off for production builds of MOSVM -- you
//   cannot and should not rely on these type checks.

#define MQO_TYPE_INLINES( tn ) \
    mqo_##tn mqo_req_##tn( mqo_value v, const char* f ); \
    mqo_##tn mqo_req_sub_##tn( mqo_value v, const char* f ); \
    static inline mqo_##tn mqo_##tn##_fv( mqo_value v ){ \
        assert( mqo_value_type( v ) == mqo_##tn##_type ); \
        return (mqo_##tn)v.data; \
    }; \
    static inline mqo_value mqo_vf_##tn( mqo_##tn x ){ \
        return (mqo_value){ mqo_##tn##_type, (mqo_integer)x }; \
    }; \
    static inline mqo_boolean mqo_is_##tn( mqo_value v ){ \
        return mqo_value_type(v) == mqo_##tn##_type; \
    }; \
    static inline mqo_boolean mqo_isa_##tn( mqo_value v ){ \
        return mqo_direct_type( v ) == mqo_##tn##_type; \
    }; \

#define MQO_DECL_TYPE( tn ) \
    extern mqo_type mqo_##tn##_type;

#define MQO_BEGIN_TYPE( tn ) \
    MQO_DECL_TYPE( tn ) \
    struct mqo_##tn##_data; \
    typedef struct mqo_##tn##_data* mqo_##tn; \
    struct mqo_##tn##_data{
    
#define MQO_END_TYPE( tn ) \
    }; \
    MQO_TYPE_INLINES( tn ) \

#define MQO_DEFN_TYPE2( sn, tn ) \
    mqo_##tn mqo_req_##tn( mqo_value v, const char* f ){ \
        if( mqo_is_##tn( v ) ){ \
            return mqo_##tn##_fv( v ); \
        }else{ \
            mqo_errf( mqo_es_args, "sx", \
                                   "expected " sn, v ); \
        } \
    } \
    mqo_##tn mqo_req_sub_##tn( mqo_value v, const char* f ){ \
        if( mqo_direct_type( v ) == mqo_##tn##_type ){ \
            return (mqo_##tn)(v.data); \
        }else{ \
            mqo_errf( mqo_es_args, "sx", \
                                   "expected subtype of " sn, v ); \
        } \
    } \
    struct mqo_type_data mqo_##tn##_type_data = { NULL, NULL, NULL, NULL }; \
    mqo_type mqo_##tn##_type = &mqo_##tn##_type_data; 

#define MQO_DEFN_TYPE( tt ) MQO_DEFN_TYPE2( ""#tt, tt );

#define MQO_BIND_TYPE2( sn, tn, di ) \
    mqo_##tn##_type_data.mt_show = (mqo_show_mt)mqo_show_##tn; \
    mqo_##tn##_type_data.direct = mqo_##di##_type; \
    mqo_##tn##_type_data.super = mqo_##di##_type; \
    mqo_##tn##_type_data.name = mqo_symbol_fs( sn ); \
    mqo_symbol_fs( "<" sn ">" )->value = mqo_vf_type( mqo_##tn##_type );

#define MQO_BIND_TYPE( tt, di ) MQO_BIND_TYPE2( #tt, tt, di );

#define mqo_nil_type NULL

#define MQO_ALLOC( tn, ext ) ((tn)GC_malloc(sizeof( struct tn##_data ) + ext ))
// GC_malloc_quarkic does not appear to work on OpenBSD, and is disabled.
// #define MQO_AALLOC( tn, ext ) ((tn)GC_malloc_quarkic(sizeof( struct tn##_data ) + ext ))

#include <assert.h>
#include <stdlib.h>

struct mqo_type_data;
typedef struct mqo_type_data* mqo_type;

struct mqo_symbol_data;
typedef struct mqo_symbol_data* mqo_symbol;

typedef struct {
    mqo_type    type;
    mqo_integer data;
} mqo_value;

struct mqo_pair_data;
typedef struct mqo_pair_data* mqo_pair;
struct mqo_pair_data{
    mqo_value car;
    mqo_value cdr;
};
MQO_DECL_TYPE( pair );

typedef void (*mqo_show_mt) (void*, mqo_word*);

struct mqo_type_data {
    mqo_type   direct;
    mqo_symbol name;
    mqo_type   super;
    mqo_pair   info;
    mqo_show_mt mt_show;
};

MQO_DECL_TYPE( type );

extern mqo_type mqo_default_type;

static inline mqo_type mqo_value_type( mqo_value value ){
    return value.type ? value.type : mqo_default_type;
}
static inline mqo_type mqo_type_direct( mqo_type type ){
    return type->direct ? type->direct : type;
}
static inline mqo_type mqo_direct_type( mqo_value value ){
    return mqo_type_direct( mqo_value_type( value ) );
}
MQO_TYPE_INLINES( type );
MQO_TYPE_INLINES( pair );

MQO_BEGIN_TYPE( string )
    mqo_integer length;
    char data[1];
MQO_END_TYPE( string )

extern mqo_type mqo_symbol_type;
struct mqo_symbol_data{
    // NOTE: Symbols "cheat" by providing slots for the value assigned to them
    //       in the top level environment.  Since the LDG opcode refers to
    //       these symbols, any time the LDG is evaluated, the value is just
    //       a pointer dereference away!
     
    mqo_string string;
    mqo_value  value;
};
MQO_TYPE_INLINES( symbol )

typedef void (*mqo_prim_fn)( );
MQO_BEGIN_TYPE( prim )
    mqo_symbol  name;
    mqo_prim_fn fn;
MQO_END_TYPE( prim )

MQO_BEGIN_TYPE( instruction )
    mqo_byte code;
    mqo_prim prim;
    union{
        mqo_symbol  sy;
        mqo_value   va;
        mqo_integer in;
        struct{
            mqo_word a;
            mqo_word b;
        }w;
    };
MQO_END_TYPE( instruction )

MQO_BEGIN_TYPE( program )
    mqo_integer length;
    struct mqo_instruction_data inst[0];
MQO_END_TYPE( program )

MQO_BEGIN_TYPE( vector )
    mqo_word  length;
    mqo_value data[0];
MQO_END_TYPE( vector )

MQO_BEGIN_TYPE( closure )
    mqo_symbol    name;
    mqo_program     cp;
    mqo_instruction ip;
    mqo_pair        ep;
MQO_END_TYPE( closure )

MQO_BEGIN_TYPE( multimethod )
    mqo_value     signature;
    mqo_value     func;
    mqo_value     next;
MQO_END_TYPE( multimethod )

MQO_BEGIN_TYPE( guard )
    mqo_value fn;
    mqo_program  cp;
    mqo_instruction ip;
    mqo_pair ep;
    mqo_integer si, ri;
MQO_END_TYPE( guard )

MQO_BEGIN_TYPE( vmstate )
    mqo_program cp;
    mqo_instruction ip;
    mqo_vector  sv, rv;
    mqo_integer si, ri;
    mqo_pair    ep, gp;
MQO_END_TYPE( vmstate )

MQO_BEGIN_TYPE( process )
    mqo_process prev, next;
    mqo_symbol status;
    mqo_vmstate state;
    mqo_value input, output;
MQO_END_TYPE( process )

MQO_BEGIN_TYPE( error )
    mqo_symbol  key;
    mqo_pair    info, context;
MQO_END_TYPE( error )

MQO_DECL_TYPE( integer );
MQO_TYPE_INLINES( integer );

MQO_DECL_TYPE( quark );
MQO_DECL_TYPE( void );

MQO_DECL_TYPE( boolean );
MQO_TYPE_INLINES( boolean );

MQO_DECL_TYPE( tc );
typedef mqo_pair mqo_tc;
MQO_TYPE_INLINES( tc );

#define MQO_CONSOLE 0
#define MQO_LISTENER 1
#define MQO_SOCKET 2
#define MQO_FILE 3

MQO_BEGIN_TYPE( descr )
    unsigned int type:2;
    unsigned int closed:1;
    
    mqo_descr next, prev;
    mqo_string name;
    mqo_integer fd;
    mqo_process monitor;
    mqo_value result;
};
mqo_descr mqo_descr_fv( mqo_value v );
mqo_value mqo_vf_descr( mqo_descr d );
mqo_boolean mqo_is_descr( mqo_value v );
mqo_descr mqo_req_descr( mqo_value v, const char* w );
mqo_descr mqo_req_sub_descr( mqo_value v, const char* w );

MQO_DECL_TYPE( socket );
typedef mqo_descr mqo_socket;
static inline mqo_boolean mqo_is_socket( mqo_value v ){
    return mqo_value_type( v ) == mqo_socket_type;
}
static inline mqo_value mqo_vf_socket( mqo_socket x ){
    return (mqo_value){ mqo_socket_type, (mqo_integer)x };
};
static inline mqo_socket mqo_socket_fv( mqo_value value ){
    assert( value.type == mqo_socket_type );
    return (mqo_socket)(value.data);
};
mqo_socket mqo_req_socket( mqo_value v, const char* w );
mqo_socket mqo_req_sub_socket( mqo_value v, const char* w );

MQO_DECL_TYPE( listener );
typedef mqo_descr mqo_listener;
static inline mqo_boolean mqo_is_listener( mqo_value v ){
    return mqo_value_type( v ) == mqo_listener_type;
}
static inline mqo_value mqo_vf_listener( mqo_listener x ){
    return (mqo_value){ mqo_listener_type, (mqo_integer)x };
};
static inline mqo_listener mqo_listener_fv( mqo_value value ){
    assert( value.type == mqo_listener_type );
    return (mqo_listener)(value.data);
};
mqo_listener mqo_req_listener( mqo_value v, const char* w );
mqo_listener mqo_req_sub_listener( mqo_value v, const char* w );

MQO_DECL_TYPE( console );
typedef mqo_descr mqo_console;
static inline mqo_boolean mqo_is_console( mqo_value v ){
    return mqo_value_type( v ) == mqo_console_type;
}
static inline mqo_value mqo_vf_console( mqo_console x ){
    return (mqo_value){ mqo_console_type, (mqo_integer)x };
};
static inline mqo_console mqo_console_fv( mqo_value value ){
    assert( value.type == mqo_console_type );
    return (mqo_console)(value.data);
};
mqo_console mqo_req_console( mqo_value v, const char* w );
mqo_console mqo_req_sub_console( mqo_value v, const char* w );

MQO_DECL_TYPE( file );
typedef mqo_descr mqo_file;
static inline mqo_boolean mqo_is_file( mqo_value v ){
    return mqo_value_type( v ) == mqo_file_type;
}
static inline mqo_value mqo_vf_file( mqo_file x ){
    return (mqo_value){ mqo_file_type, (mqo_integer)x };
};
static inline mqo_file mqo_file_fv( mqo_value value ){
    assert( value.type == mqo_file_type );
    return (mqo_file)(value.data);
};
mqo_file mqo_req_file( mqo_value v, const char* w );
mqo_file mqo_req_sub_file( mqo_value v, const char* w );

typedef mqo_value (*mqo_key_fn) (mqo_value);

MQO_BEGIN_TYPE( node )
    mqo_long weight;
    mqo_value data;
    mqo_node left, right;
MQO_END_TYPE( node )

MQO_BEGIN_TYPE( tree )
    mqo_node root;
    mqo_key_fn key_fn;
MQO_END_TYPE( tree )

MQO_DECL_TYPE( set )
typedef mqo_tree mqo_set;
MQO_TYPE_INLINES( set )

MQO_DECL_TYPE( dict );
typedef mqo_tree mqo_dict;
MQO_TYPE_INLINES( dict );

extern mqo_tree mqo_lexicon;
extern mqo_value mqo_nil;


static inline mqo_value mqo_vf_false( ){
    return mqo_vf_boolean(0);
}
static inline mqo_value mqo_vf_true( ){
    return mqo_vf_boolean(1);
}
static inline mqo_value mqo_vf_empty( ){
    return mqo_vf_pair( (mqo_pair)NULL );
}

static inline int mqo_is_false( mqo_value v ){
    return ( mqo_is_boolean( v ) )&&( ! v.data );
}
static inline int mqo_is_true( mqo_value v ){
    return ( mqo_is_boolean( v ) )&&( v.data );
}
static inline int mqo_is_empty( mqo_value v ){
    return ( mqo_is_pair( v ) )&&( ! v.data );
}

static inline mqo_value mqo_car( mqo_pair p ){ 
    assert( p ); 
    return p->car; 
}
static inline mqo_value mqo_cdr( mqo_pair p ){ 
    assert( p ); 
    return p->cdr; 
}
static inline void mqo_set_car( mqo_pair p, mqo_value v ){ 
    assert( p ); 
    p->car = v; 
}
static inline void mqo_set_cdr( mqo_pair p, mqo_value v ){ 
    assert( p ); 
    p->cdr = v; 
}

mqo_type mqo_make_type( mqo_symbol name, mqo_type super, 
                        mqo_show_mt mt_show,
                        mqo_pair info );
mqo_error mqo_make_error( mqo_symbol key, mqo_pair info, mqo_pair context );
mqo_process mqo_make_process( );
mqo_string mqo_make_string( mqo_integer length );
mqo_guard mqo_make_guard( mqo_value fn, mqo_integer ri, mqo_integer si, mqo_program cp, mqo_instruction ip, mqo_pair ep );
mqo_closure mqo_make_closure( mqo_program cp, mqo_instruction ip, mqo_pair ep );
mqo_vector mqo_make_vector( mqo_integer length );
mqo_program mqo_make_program( mqo_integer length );
mqo_descr mqo_make_descr( mqo_string path, int fd, mqo_byte type );
mqo_socket mqo_make_socket( mqo_string path, int fd );
mqo_file mqo_make_file( mqo_string path, int fd );
mqo_listener mqo_make_listener( mqo_string path, int fd );
mqo_console mqo_make_console( mqo_string path );

static inline mqo_integer mqo_vector_length( mqo_vector v ){ 
    return v->length; 
}
static inline mqo_value *mqo_vector_ref( mqo_vector v, mqo_integer offset ){
    assert( 0 <= offset );
    assert( offset < v->length ); 
    return v->data + offset;
}
static inline mqo_value mqo_vector_get( mqo_vector v, mqo_integer offset ){ 
    return *(mqo_vector_ref( v, offset )); 
}
static inline void mqo_vector_put( mqo_vector v, mqo_integer offset, 
                                   mqo_value x ){
    *(mqo_vector_ref( v, offset )) = x; 
}

mqo_vector mqo_copy_vector( mqo_vector vo, mqo_integer ln );

mqo_pair mqo_list_ref( mqo_pair p, mqo_integer offset );

mqo_pair mqo_cons( mqo_value a, mqo_value b );

mqo_string mqo_string_fm( const void* s, mqo_integer length );
mqo_string mqo_string_fs( const char* s );
static inline const char* mqo_sf_string( mqo_string a ){ assert( a ); return a->data; }
static inline mqo_integer mqo_string_length( mqo_string s ){ assert( s ); return s->length; }

mqo_symbol mqo_symbol_fm( const void* s, mqo_integer length );
mqo_symbol mqo_symbol_fs( const char* s );
mqo_value  mqo_symbol_value( mqo_symbol sym );
mqo_string mqo_symbol_string( mqo_symbol sym );

mqo_tc mqo_make_tc( );
void mqo_tc_append( mqo_pair tc, mqo_value v );
// Appends a value to a tconc list.

static inline int mqo_eq( mqo_value a, mqo_value b ){
    return ( mqo_value_type( a ) == mqo_value_type( b ) )&&( a.data == b.data );
}

mqo_vmstate mqo_make_vmstate( );
mqo_prim mqo_make_prim( mqo_symbol name, mqo_prim_fn fn );

mqo_process mqo_make_process( );
mqo_multimethod mqo_make_multimethod( 
   mqo_value signature, mqo_value func, mqo_value next
);

void mqo_init_memory_subsystem();

#define MQO_FOREACH( list, pair ) \
    for( mqo_pair pair = list; \
         pair != NULL; \
         pair = mqo_pair_fv( mqo_cdr( pair ) ) )


mqo_boolean mqo_isa( mqo_value v, mqo_type t );
static inline mqo_value mqo_make_value( mqo_type type, mqo_integer data ){
    return (mqo_value){ type, data };
}
static inline mqo_boolean mqo_is_function( mqo_value v ){
    return (
        mqo_is_closure(v) || mqo_is_prim(v) || 
        mqo_is_program(v) || mqo_is_multimethod(v)
    );
}

static inline mqo_value mqo_make_quark( ){
    return (mqo_value){ mqo_quark_type, 0 };
}
static mqo_boolean mqo_isa_quark( mqo_value v ){
    return mqo_isa( v, mqo_quark_type );
}
static inline mqo_value mqo_make_void( ){
    return (mqo_value){ mqo_void_type, 0 };
}
static mqo_boolean mqo_is_void( mqo_value v ){
    return mqo_isa( v, mqo_void_type );
}

mqo_integer mqo_compare( mqo_value v1, mqo_value v2 );
mqo_boolean mqo_eqv( mqo_value v1, mqo_value v2 );
mqo_boolean mqo_eqvs( mqo_string v1, mqo_string v2 );
mqo_boolean mqo_eqvv( mqo_vector v1, mqo_vector v2 );
mqo_boolean mqo_eqvp( mqo_pair v1, mqo_pair v2 );

//TODO: Warning -- our equal function does not recognize recursion.
mqo_boolean mqo_equal( mqo_value v1, mqo_value v2 );
#define mqo_equals mqo_eqvs;
mqo_boolean mqo_equalv( mqo_vector v1, mqo_vector v2 );
mqo_boolean mqo_equalp( mqo_pair v1, mqo_pair v2 );
mqo_pair mqo_last_pair( mqo_pair p );

#define mqo_list mqo_pair
mqo_list mqo_req_list( mqo_value v, const char* s );

mqo_instruction mqo_program_ref( mqo_program p, mqo_integer i );

mqo_value mqo_set_key( mqo_value item );
mqo_value mqo_dict_key( mqo_value item ); 

#endif
