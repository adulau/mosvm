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
 * aquad with this library; if not, write to the Free Software Foundation, 
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

#ifndef MQO_MEMORY_H
#define MQO_MEMORY_H 1

#include <stdlib.h>
#include <assert.h>

// Standard integers
#if defined( __OpenBSD__ )

typedef unsigned char mqo_byte;
typedef unsigned short mqo_word;
typedef unsigned long mqo_quad;
typedef signed long mqo_integer;
typedef int mqo_boolean;

#else

#include <stdint.h>

typedef uint8_t mqo_byte;
typedef uint16_t mqo_word;
typedef uint32_t mqo_quad;
typedef int32_t mqo_integer;
typedef int mqo_boolean;

#endif

// Type Macros
#define MQO_H_TP( tn ) \
    extern const char* mqo_##tn##_name; \
    extern mqo_type mqo_##tn##_type;

#define MQO_H_RQ( tn ) \
    mqo_##tn mqo_req_##tn( mqo_value );

#define MQO_H_FV( tn ) \
    static inline mqo_##tn mqo_##tn##_fv( mqo_value val ){ \
        assert( mqo_is_##tn( val ) ); \
        return (mqo_##tn) val; \
    } 

#define MQO_H_VF( tn ) \
    static inline mqo_value mqo_vf_##tn( mqo_##tn val ){ \
        return mqo_vf_obj( (mqo_object) val ); \
    }

#define MQO_H_IS( tn ) \
    static inline int mqo_is_##tn( mqo_value val ){ \
        return mqo_is_obj( val ) &&( \
            mqo_obj_type( mqo_obj_fv( val ) ) == mqo_##tn##_type \
        ); \
    }

#define REQ_ANY_ARG( vn ) \
    mqo_value vn = mqo_req_any();

#define REQ_TYPED_ARG( vn, tn ) \
    mqo_##tn vn = mqo_##tn##_fv( mqo_req_arg( mqo_##tn##_type ) );

#define REQ_FUNCTION_ARG( vn ) \
    mqo_value vn = mqo_req_function( mqo_req_any( ) );

#define OPT_ANY_ARG( vn ) \
    mqo_boolean has_##vn; \
    mqo_value vn = mqo_opt_any( &has_##vn );

#define MQO_H_SUBTYPE( st, dt ) \
    typedef mqo_##dt mqo_##st; \
    MQO_H_TYPE( st ) \

#ifdef NDEBUG

#define OPT_TYPED_ARG( vn, tn ) \
    mqo_boolean has_##vn; \
    mqo_##tn vn = mqo_##tn##_fv( mqo_opt_arg( mqo_##tn##_type, &has_##vn ) );

#else
// The fv assertions may freak out when they see a null..

#define OPT_TYPED_ARG( vn, tn ) \
    mqo_boolean has_##vn; \
    mqo_value vvv_##vn = mqo_opt_arg( mqo_##tn##_type, &has_##vn ); \
    mqo_##tn vn = has_##vn ? mqo_##tn##_fv( vvv_##vn ) : ( (mqo_##tn) 0 );

#endif

#define TYPED_RESULT( tn, x ) RESULT( mqo_vf_##tn( x ) );
#define NO_RESULT( ) RESULT( mqo_vf_null() );
#define RESULT( x )  { MQO_RX = (x); return; }

#define MQO_C_TP2( tn, ts ) \
    const char* mqo_##tn##_name = ts; \
    struct mqo_type_data mqo_##tn##_type_data = { { NULL, NULL, NULL, NULL }, NULL, NULL }; \
    mqo_type mqo_##tn##_type = &mqo_##tn##_type_data;

#define MQO_C_TP( tn ) MQO_C_TP2( tn, #tn );

#define MQO_C_RQ( tn ) \
    mqo_##tn mqo_req_##tn( mqo_value val ){ \
        if( mqo_value_type( val ) == mqo_##tn##_type ) \
            return (mqo_##tn) mqo_obj_fv( val ); \
        mqo_errf( mqo_es_vm, "sxx", "type mismatch", mqo_##tn##_type, val ); \
    } 

#define MQO_I_TYPE__( tn ) \
    mqo_##tn##_type->format = (mqo_format_mt)mqo_format_##tn; \
    mqo_##tn##_type->trace = (mqo_gc_mt)mqo_trace_##tn; \
    mqo_##tn##_type->free = (mqo_gc_mt)mqo_free_##tn; \
    mqo_##tn##_type->compare = (mqo_cmp_mt)mqo_##tn##_compare; \
    mqo_##tn##_type->header.type = mqo_type_type; \
    mqo_root_obj( (mqo_object)mqo_##tn##_type ); \

#define MQO_I_TYPE_( tn ) \
    MQO_I_TYPE__( tn ) \
    mqo_bind_type( mqo_##tn##_name, mqo_##tn##_type ); \
    
#define MQO_I_TYPE( tn ) \
    mqo_##tn##_type->direct = mqo_##tn##_type; \
    MQO_I_TYPE_( tn );

#define MQO_C_SUBTYPE( chil, pare ) \
    MQO_C_TYPE( chil );

#define MQO_I_SUBTYPE( child, pare ) \
    mqo_##child##_type->format = (mqo_format_mt)mqo_format_##pare; \
    mqo_##child##_type->trace = (mqo_gc_mt)mqo_trace_##pare; \
    mqo_##child##_type->free = (mqo_gc_mt)mqo_free_##pare; \
    mqo_##child##_type->compare = (mqo_cmp_mt)mqo_##pare##_compare; \
    mqo_##child##_type->direct = mqo_##pare##_type->direct; \
    mqo_##child##_type->parent = mqo_##pare##_type; \
    mqo_##child##_type->header.type = mqo_type_type; \
    mqo_root_obj( (mqo_object)mqo_##child##_type ); \
    mqo_bind_type( mqo_##child##_name, mqo_##child##_type ); \

#define MQO_H_TYPE( tn ) \
    MQO_H_TP( tn ); \
    MQO_H_RQ( tn ); \
    MQO_H_IS( tn ); \
    MQO_H_FV( tn ); \
    MQO_H_VF( tn ); 

#define MQO_C_TYPE2( tn, ts ) \
    MQO_C_TP2( tn, ts ); \
    MQO_C_RQ( tn );

#define MQO_C_TYPE( tn ) \
    MQO_C_TYPE2( tn, #tn ); 

#define MQO_BEGIN_TYPE( tn ) \
    struct mqo_##tn##_data; \
    typedef struct mqo_##tn##_data* mqo_##tn; \
    struct mqo_##tn##_data{ \
        struct mqo_object_data header; \

#define MQO_END_TYPE( tn ) \
    }; \
    MQO_H_TYPE( tn )

// Fundamental Structures and Constants
typedef mqo_quad mqo_value;

struct mqo_type_data;
typedef struct mqo_type_data* mqo_type;

struct mqo_object_data;
typedef struct mqo_object_data* mqo_object;

struct mqo_pool_data;
typedef struct mqo_pool_data* mqo_pool;

extern mqo_pool mqo_greys, mqo_whites, mqo_blacks, mqo_roots;

#define MQO_MAX_IMM 1073741823
#define MQO_MIN_IMM 0

#define MQO_MAX_INT 2147483646
#define MQO_MIN_INT -2147483646 

struct mqo_object_data {
    mqo_type type;
    mqo_pool pool;
    mqo_object prev, next;
};

struct mqo_pool_data {
    mqo_object head;
};

void mqo_set_pool( mqo_object obj, mqo_pool pool );
void mqo_trace_obj( mqo_object obj );
void mqo_grey_obj( mqo_object obj );
void mqo_root_obj( mqo_object obj );
void mqo_trace_all( );

MQO_H_TP( null );
static inline mqo_boolean mqo_is_null( mqo_value val ){ return ! val; };
static inline mqo_value mqo_vf_null( ){ return 0; }

extern mqo_type mqo_imm_type;

// Fundamental Conversions & Accessors
static inline int mqo_is_imm( mqo_value val ){ return val & 1; }
static inline int mqo_is_obj( mqo_value val ){ return ! mqo_is_imm( val ); }
static inline mqo_object mqo_obj_fv( mqo_value val ){
    assert( mqo_is_obj( val ) );
    return (mqo_object) val;    
}
static inline mqo_quad mqo_imm_fv( mqo_value val ){
    assert( mqo_is_imm( val ) );
    return (mqo_quad)( val >> 1 );
}
static inline mqo_type mqo_obj_type( mqo_object obj ){
    return obj ? obj->type : mqo_null_type;
}

static inline mqo_type mqo_value_type( mqo_value val ){
    if( mqo_is_obj( val ) ) return mqo_obj_type( mqo_obj_fv( val ) );
    return mqo_imm_type;
}

static inline mqo_value mqo_vf_obj( mqo_object obj ){
    assert( !( ( (mqo_quad) obj) & 1 ) );
    return (mqo_value) obj;
}

static inline mqo_value mqo_vf_imm( mqo_quad imm ){
    assert( imm < ( 1 << 31 ) );
    return( imm << 1) | 1;
}


// Fundamental Memory Operations
#define MQO_OBJALLOC( tn ) MQO_OBJALLOC2( tn, 0 )
#define MQO_OBJALLOC2( tn, sz ) \
    ( (mqo_##tn) mqo_objalloc( mqo_##tn##_type, \
                               sizeof( struct mqo_##tn##_data ) + (sz) ) )

mqo_object mqo_objalloc( mqo_type type, mqo_quad size );
void mqo_objfree( void* obj );

typedef void (*mqo_gc_mt)( mqo_object obj );
typedef mqo_integer (*mqo_cmp_mt)( mqo_value a, mqo_value b );
typedef void (*mqo_format_mt)( void*, mqo_value obj );

#define MQO_INHERIT_MT( child, parent ) \
    MQO_INHERIT_GC( child, parent ); \
    MQO_INHERIT_FORMAT( child, parent ); \
    MQO_INHERIT_COMPARE( child, parent );

#define MQO_GENERIC_MT( type ) \
    MQO_GENERIC_GC( type ); \
    MQO_GENERIC_FORMAT( type ); \
    MQO_GENERIC_COMPARE( type );

#define MQO_INHERIT_GC( child, parent ) \
    MQO_INHERIT_TRACE( child, parent ); \
    MQO_INHERIT_FREE( child, parent );

#define MQO_GENERIC_GC( type ) \
    MQO_GENERIC_TRACE( type ); \
    MQO_GENERIC_FREE( type ); \

#define MQO_GENERIC_TRACE( type ) \
    const mqo_gc_mt mqo_trace_##type = mqo_generic_trace; \

#define MQO_GENERIC_FREE( type ) \
    const mqo_gc_mt mqo_free_##type = mqo_generic_free; 

#define MQO_GENERIC_COMPARE( type ) \
    const mqo_cmp_mt mqo_##type##_compare = mqo_compare_generic;

#define MQO_GENERIC_FORMAT( type ) \
    const mqo_format_mt mqo_format_##type = (mqo_format_mt) mqo_generic_format; 

#define MQO_INHERIT_TRACE( child, parent ) \
    const mqo_gc_mt mqo_trace_##child = (mqo_gc_mt) mqo_trace_##parent; \

#define MQO_INHERIT_FREE( child, parent ) \
    const mqo_gc_mt mqo_free_##child = (mqo_gc_mt) mqo_free_##parent; \

#define MQO_INHERIT_FORMAT( child, parent ) \
    const mqo_format_mt mqo_format_##child = (mqo_format_mt) mqo_format_##parent; \

#define MQO_INHERIT_COMPARE( child, parent ) \
    const mqo_cmp_mt mqo_##child##_compare = (mqo_cmp_mt) mqo_##parent##_compare; \

void mqo_generic_format( void* buf, mqo_word* ct );
void mqo_generic_trace( mqo_object obj );
void mqo_generic_free( mqo_object obj );
mqo_integer mqo_compare_generic( mqo_value a, mqo_value b );

mqo_integer mqo_cmp_eq( mqo_value a, mqo_value b );
mqo_integer mqo_cmp_eqv( mqo_value a, mqo_value b );

static inline mqo_boolean mqo_eq( mqo_value a, mqo_value b ){
    return ! mqo_cmp_eq( a, b );
}
static inline mqo_boolean mqo_eqv( mqo_value a, mqo_value b ){
    return ! mqo_cmp_eqv( a, b );
}

// The Type Type -- Yes, the redundant redundancy is necessary..
struct mqo_type_data {
    struct mqo_object_data header;
    mqo_type parent;
    mqo_type direct;
    mqo_gc_mt trace;
    mqo_gc_mt free;
    mqo_cmp_mt compare;
    mqo_format_mt format;
    mqo_value name;
    mqo_value info;
};

MQO_H_TYPE( type );
#define REQ_TYPE_ARG( vn ) REQ_TYPED_ARG( vn, type )
#define OPT_TYPE_ARG( vn ) OPT_TYPED_ARG( vn, type )
#define TYPE_RESULT( x ) TYPED_RESULT( type, x )

static inline void mqo_grey_val( mqo_value val ){
    if( mqo_is_obj( val ) )mqo_grey_obj( mqo_obj_fv( val ) );
}

#ifdef MQO_COUNT_GC
extern mqo_quad mqo_object_ct;
#endif 

void mqo_bind_type( const char* name, mqo_type type );

void mqo_collect_garbage( );
void mqo_collect_window( );

mqo_boolean mqo_equal( mqo_value a, mqo_value b );
mqo_boolean mqo_eqv( mqo_value a, mqo_value b );
mqo_boolean mqo_eq( mqo_value a, mqo_value b );

void mqo_init_memory_subsystem( );

mqo_value mqo_req_any( );
mqo_value mqo_req_arg( mqo_type type );
mqo_value mqo_opt_any( mqo_boolean* found );
mqo_value mqo_opt_arg( mqo_type type, mqo_boolean* found );

void mqo_no_more_args( );

mqo_type mqo_make_type( mqo_value name, mqo_type parent, mqo_value info );
mqo_type mqo_direct_type( mqo_value value );
#endif
