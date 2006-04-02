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

#ifndef MQO_PRIM_H 
#define MQO_PRIM_H 1

#include "memory.h"

#define MQO_PRIM_NAME( pn ) mqo_prim_##pn##_name
#define MQO_PRIM_FUNC( pn ) mqo_prim_##pn
#define MQO_DECL_PRIM( pn ) \
  void MQO_PRIM_FUNC( pn )( ); \
  extern const char* MQO_PRIM_NAME( pn );

#define MQO_BEGIN_PRIM( id, pn ) \
   const char* MQO_PRIM_NAME( pn ) = id; \
   void MQO_PRIM_FUNC( pn )( ){ \
      mqo_integer ct = mqo_peek_int_ds(); \
      mqo_integer ai = 0; \
      mqo_value rs = mqo_vf_false( );

#define MQO_END_PRIM( pn ) \
    exeunt:  \
        mqo_drop_ds( mqo_pop_int_ds() ); \
        mqo_push_ds( rs ); \
		mqo_return( ); \
    } \

#define MQO_RESULT( v ) rs = v; goto exeunt;
#define MQO_NO_RESULT( v ) goto exeunt;

#define MQO_BEGIN_PRIM_BINDS( )\
    mqo_symbol _sym; \
    mqo_prim   _prim; \

#define MQO_BIND_PRIM( pn ) \
    _sym = mqo_symbol_fs( MQO_PRIM_NAME( pn ) ); \
    _prim = mqo_make_prim( _sym, mqo_prim_##pn ); \
    _sym->value = mqo_vf_prim( _prim );

#define REQ_VALUE_ARG( nm ) \
    if( ai >= ct ){ \
        mqo_errf( mqo_es_args, "s", "missing argument " #nm ); \
    }; \
    mqo_value nm = mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 ); \
    ai ++;

#define REQ_VALUE_TYPE( nm, tp ) \
    mqo_##tp nm = mqo_req_##tp( v_##nm, #nm );

#define REQ_VALUE_SUBTYPE( nm, tp ) \
    mqo_##tp nm = mqo_req_sub_##tp( v_##nm, #nm );

#define REQ_TYPED_ARG( nm, tp ) \
    if( ai >= ct ){ \
        mqo_errf( mqo_es_args, "s", "missing " #tp " argument " #nm ); \
    }; \
    mqo_value v_##nm = mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 ); \
    REQ_VALUE_TYPE( nm, tp ) \
    ai ++;

#define REQ_SUBTYPED_ARG( nm, tp ) \
    if( ai >= ct ){ \
        mqo_errf( mqo_es_args, "s", "missing " #tp " argument " #nm ); \
    }; \
    mqo_value v_##nm = mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 ); \
    REQ_VALUE_SUBTYPE( nm, tp ) \
    ai ++;

#define REQ_TYPE_ARG( nm )      REQ_TYPED_ARG( nm, type );
#define REQ_PAIR_ARG( nm )      REQ_TYPED_ARG( nm, pair );
#define REQ_PROGRAM_ARG( nm )   REQ_TYPED_ARG( nm, program );
#define REQ_PROCESS_ARG( nm )   REQ_TYPED_ARG( nm, process );
#define REQ_TC_ARG( nm )        REQ_TYPED_ARG( nm, tc );
#define REQ_VECTOR_ARG( nm )    REQ_TYPED_ARG( nm, vector );
#define REQ_SET_ARG( nm )       REQ_TYPED_ARG( nm, set );
#define REQ_DICT_ARG( nm )      REQ_TYPED_ARG( nm, dict );
#define REQ_INTEGER_ARG( nm )   REQ_TYPED_ARG( nm, integer );
#define REQ_ERROR_ARG( nm )     REQ_TYPED_ARG( nm, error );
#define REQ_VMSTATE_ARG( nm )   REQ_TYPED_ARG( nm, vmstate );
#define REQ_STRING_ARG( nm )    REQ_TYPED_ARG( nm, string );
#define REQ_BUFFER_ARG( nm )    REQ_TYPED_ARG( nm, buffer );
#define REQ_SYMBOL_ARG( nm )    REQ_TYPED_ARG( nm, symbol );
#define REQ_DESCR_ARG( nm )     REQ_TYPED_ARG( nm, descr );
#define REQ_ANY_DESCR_ARG( nm ) REQ_SUBTYPED_ARG( nm, descr );
#define REQ_FILE_ARG( nm )      REQ_TYPED_ARG( nm, file );
#define REQ_LIST_ARG( nm )      REQ_TYPED_ARG( nm, list );
#define REQ_REGEX_ARG( nm )     REQ_TYPED_ARG( nm, regex );
    
#define REQ_RANGED_ARG( nm, min, max ) \
    REQ_INTEGER_ARG( nm ); \
    if(! ( min <= nm ) && ( nm <= max ) ){ \
        mqo_errf( mqo_es_args, "si", #nm "must be between " #min " and " #max, \
                  nm ); \
    } \

#define REQ_BYTE_ARG( nm )      REQ_RANGED_ARG( nm, 0, 255 );
#define REQ_WORD_ARG( nm )      REQ_RANGED_ARG( nm, 0, 65535 );
#define REQ_QUAD_ARG( nm )      REQ_INTEGER_ARG( nm );

#define REST_ARGS( nm )         mqo_pair nm = mqo_rest( ct - ai, 1 ); \
                                ai = ct; \

#define ERR_IF_NULL( v ) \
    if( ! v ){ mqo_errf( mqo_es_vm, "s", #v "may not be null" ); };

#define OPT_VALUE_ARG( nm ) \
    mqo_value nm; \
    int has_##nm; \
    if( ai < ct ){ \
        has_##nm = 1; \
        nm = mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 ); \
        ai ++; \
    }else{ \
        has_##nm = 0; \
        nm = (mqo_value){mqo_void_type, 0}; \
    }; 
                            
#define OPT_TYPED_ARG( nm, tp, df ) \
    mqo_value v_##nm; \
    mqo_##tp nm; \
    int has_##nm; \
    if( ai < ct ){ \
        has_##nm = 1; \
        v_##nm = mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 ); \
        nm = mqo_req_##tp( v_##nm, #nm ); \
        ai ++; \
    }else{ \
        has_##nm = 0; \
        nm = df; \
    };

#define OPT_TYPE_ARG( nm )    OPT_TYPED_ARG( nm, type, NULL );
#define OPT_PAIR_ARG( nm )    OPT_TYPED_ARG( nm, pair, NULL );
#define OPT_PROGRAM_ARG( nm ) OPT_TYPED_ARG( nm, program, NULL );
#define OPT_PROCESS_ARG( nm ) OPT_TYPED_ARG( nm, process, NULL );
#define OPT_TC_ARG( nm )      OPT_TYPED_ARG( nm, tc, NULL );
#define OPT_VECTOR_ARG( nm )  OPT_TYPED_ARG( nm, vector, NULL );
#define OPT_INTEGER_ARG( nm ) OPT_TYPED_ARG( nm, integer, 0 );
#define OPT_ERROR_ARG( nm )   OPT_TYPED_ARG( nm, error, NULL );
#define OPT_VMSTATE_ARG( nm ) OPT_TYPED_ARG( nm, vmstate, NULL );
#define OPT_STRING_ARG( nm )  OPT_TYPED_ARG( nm, string, NULL );
#define OPT_BUFFER_ARG( nm )  OPT_TYPED_ARG( nm, buffer, NULL );
#define OPT_SYMBOL_ARG( nm )  OPT_TYPED_ARG( nm, symbol, NULL );
#define OPT_DESCR_ARG( nm )   OPT_TYPED_ARG( nm, descr, NULL );
#define OPT_LIST_ARG( nm )    OPT_TYPED_ARG( nm, list, NULL );

#define NO_MORE_ARGS( ) \
    if( ai < ct ){ \
        mqo_errf( mqo_es_args, "sx", "too many arguments", mqo_vector_get( MQO_SV, MQO_SI + ai - ct - 1 ) ); \
    }; 

static inline mqo_value mqo_peek_ds( ){
    assert( MQO_SI );
    return mqo_vector_get( MQO_SV, MQO_SI - 1 );
}
static inline mqo_integer mqo_peek_int_ds( ){
    return mqo_integer_fv( mqo_peek_ds( ) );
}
static inline mqo_pair mqo_peek_pair_ds( ){
    return mqo_pair_fv( mqo_peek_ds( ) );
}
static inline mqo_vector mqo_peek_vect_ds( ){
    return mqo_vector_fv( mqo_peek_ds( ) );
}

static inline mqo_value mqo_pop_ds( ){
    assert( MQO_SI );
    return mqo_vector_get( MQO_SV, -- MQO_SI );
}
static inline mqo_integer mqo_pop_int_ds( ){
    return mqo_integer_fv( mqo_pop_ds( ) );
}
static inline mqo_pair mqo_pop_pair_ds( ){
    return mqo_pair_fv( mqo_pop_ds( ) );
}
static inline mqo_vector mqo_pop_vect_ds( ){
    return mqo_vector_fv( mqo_pop_ds( ) );
}

static inline void mqo_push_ds( mqo_value x ){
    assert( MQO_SI < MQO_STACK_SZ );
    mqo_vector_put( MQO_SV, MQO_SI++, x );
}
static inline void mqo_push_int_ds( mqo_integer x ){
    mqo_push_ds( mqo_vf_integer( x ) );
}
static inline void mqo_push_pair_ds( mqo_pair x ){
    mqo_push_ds( mqo_vf_pair( x ) );
}
static inline void mqo_push_vect_ds( mqo_vector x ){
    mqo_push_ds( mqo_vf_vector( x ) );
}
static inline void mqo_drop_ds( mqo_integer ct ){
    assert( MQO_SI >= ct );
    MQO_SI -= ct;
}

static inline mqo_value mqo_peek_rs( ){
    assert( MQO_RI );
    return mqo_vector_get( MQO_RV, MQO_RI - 1 );
}
static inline mqo_integer mqo_peek_int_rs( ){
    return mqo_integer_fv( mqo_peek_rs( ) );
}
static inline mqo_pair mqo_peek_pair_rs( ){
    return mqo_pair_fv( mqo_peek_rs( ) );
}
static inline mqo_vector mqo_peek_vect_rs( ){
    return mqo_vector_fv( mqo_peek_rs( ) );
}

static inline mqo_value mqo_pop_rs( ){
    assert( MQO_RI );
    return mqo_vector_get( MQO_RV, -- MQO_RI );
}
static inline mqo_integer mqo_pop_int_rs( ){
    return mqo_integer_fv( mqo_pop_rs( ) );
}
static inline mqo_pair mqo_pop_pair_rs( ){
    return mqo_pair_fv( mqo_pop_rs( ) );
}
static inline mqo_vector mqo_pop_vect_rs( ){
    return mqo_vector_fv( mqo_pop_rs( ) );
}

static inline void mqo_push_rs( mqo_value x ){
    assert( MQO_RI < MQO_STACK_SZ );
    mqo_vector_put( MQO_RV, MQO_RI++, x );
}
static inline void mqo_push_int_rs( mqo_integer x ){
    mqo_push_rs( mqo_vf_integer( x ) );
}
static inline void mqo_push_pair_rs( mqo_pair x ){
    mqo_push_rs( mqo_vf_pair( x ) );
}
static inline void mqo_push_vect_rs( mqo_vector x ){
    mqo_push_rs( mqo_vf_vector( x ) );
}
static inline void mqo_drop_rs( mqo_integer ct ){
    assert( MQO_RI >= ct );
    MQO_RI -= ct;
}

// #define mqo_vread( r )         ( mqo_vector_get( MQO_ ## r ## V, \
                                                    MQO_ ## r ## I ++ ) )

#define mqo_vpush( r, x )      ( mqo_vector_put( MQO_ ## r ## V, \
                                                 MQO_ ## r ## I ++, \
                                                 x ) )
#define mqo_vpushp( r, p )     ( mqo_vpush( r, mqo_vf_pair( p ) ) )
#define mqo_vpushv( r, v )     ( mqo_vpush( r, mqo_vf_vector( v ) ) )

#define mqo_vdrop( r, i )      ( MQO_## r ## I -= i )

mqo_pair mqo_rest( mqo_integer ct, mqo_integer ofs );

#endif

