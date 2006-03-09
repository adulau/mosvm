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
#include <tomcrypt.h>

#define OPT_RANDOM_ARG( nm ) OPT_TYPED_ARG( nm, random, mqo_default_random );

MQO_BEGIN_TYPE( random )
    int foo;
    const struct ltc_prng_descriptor* descr;
    prng_state state;
MQO_END_TYPE( random )

mqo_symbol mqo_es_crypto = NULL;
mqo_random mqo_default_random = NULL;

void mqo_show_random( mqo_random random, mqo_word* ct ){
    mqo_write( "[random ");
    mqo_write( random->descr->name );
    mqo_write( "]" );
}

MQO_DEFN_TYPE( random )

mqo_integer mqo_crypto_err( mqo_integer result ){
    if( result != CRYPT_OK ){
    assert( 0 );
        mqo_errf( mqo_es_crypto, "s", error_to_string( result ) );
    }
    return result;
}

mqo_integer mqo_random_err( mqo_integer request, mqo_integer actual ){
    if( actual < request ){
        mqo_errf( mqo_es_crypto, "s", 
                  "the OS entropy provider could not provide sufficient"
                  " entropy" );
    }
}

void mqo_read_random( mqo_random random, void* dest, mqo_long len ){
    mqo_random_err( len, random->descr->read( dest, len, &( random->state ) ) );
}

mqo_long mqo_random_long( mqo_random random ){
    mqo_long result;
    mqo_read_random( random, &result, sizeof( result ) );
    return result;
}

mqo_integer mqo_random_integer( mqo_random random, mqo_integer min, 
                                mqo_integer max ){
    // Returns a random integer in the range (min, max)
    mqo_integer temp;

    if( min > max ){ temp = max; max = min; min = temp; }

    // base the number of integers in (min, max]
    mqo_long base = (mqo_long)( max - min );

    // Handle 0xFFFFFFFF - 0x7FFFFFFF case

    // In case the user was an idiot and gave us min == max
    if( base == 0 ) return min;
   
    // In case the user specified ( MININT, MAXINT ), which our curbing
    // algorithm won't handle, due to overflow.
    // Our curbing algorithm cannot handle that, but mqo_random_long is 
    // really what he's asking for.
    if( base == 0xFFFFFFFF ) return (mqo_integer)mqo_random_long( random );

    // We bump the base by one, so it now counts (min, max)
    base ++;
   
    // If the base is not a power of 2, then there will be an uneven
    // distribution over the lower portion of the field if we just do an
    // innocent modulus.  Therefore, we must identify the greatest multiple
    // of the base that is below are maximum possible integer.
    mqo_long maxrnd = (mqo_long)( ( (unsigned long long)0x100000000 ) 
                                  / base * base - 1 );
    
    mqo_long rnd;
    
    for(;;){ rnd = mqo_random_long( random ); if( rnd <= maxrnd ) break; }

    return min + rnd % base;
}

mqo_random mqo_make_random( const struct ltc_prng_descriptor* descr, const void* init, int initlen ){
    mqo_random random = MQO_ALLOC( mqo_random, 0 );
    random->descr = descr;

    // mqo_crypto_err( random->descr->start( &( random->state ) ) );

#if defined( SPRNG )
    if( descr == &sprng_desc ){}else
#endif
    if( init ){
        mqo_crypto_err( random->descr->pimport( init, 
                                                initlen, 
                                                &( random->state ) ) );
    }else{
        static char seed[ 1024 ];
        int seed_cycles = 32;
        char* seedptr = seed;

        if( mqo_default_random ){
            //TODO
            mqo_read_random( mqo_default_random, seed, 1024 );
        }else{
            mqo_random_err( 1024, rng_get_bytes( seed, 1024, NULL ) );
        }
    
        while( --seed_cycles ){
            mqo_crypto_err( random->descr->add_entropy( seed, 32, 
                                                        &(random->state ) ) );
            seedptr += 32;
        }
    }

    mqo_crypto_err( random->descr->ready( &( random->state ) ) );

    return random;
}

MQO_BEGIN_PRIM( "make-random", make_random )
    REQ_STRING_ARG( type );
    OPT_STRING_ARG( init );
    NO_MORE_ARGS( );
   
    int id = find_prng( mqo_sf_string( type ) );
    if( id == -1 ) mqo_errf( mqo_es_crypto, "s", "could not find prng" );
    struct ltc_prng_descriptor* descr = prng_descriptor + id;
    mqo_random rng;
    
    if( has_init ){
        rng = mqo_make_random( descr, mqo_sf_string( init ),
                            mqo_string_length( init ) );
    }else{    
        rng = mqo_make_random( descr, NULL, 0 );
    }

    MQO_RESULT( mqo_vf_random( rng ) );
MQO_END_PRIM( make_random )

MQO_BEGIN_PRIM( "add-entropy", add_entropy )
    REQ_STRING_ARG( entropy );
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );

    mqo_crypto_err( random->descr->add_entropy( mqo_sf_string( entropy ),
                                                mqo_string_length( entropy ),
                                                &( random->state ) ) );

    mqo_crypto_err( random->descr->ready( &( random->state ) ) );

    MQO_NO_RESULT( );
MQO_END_PRIM( add_entropy )

MQO_BEGIN_PRIM( "random-string", random_string )
    REQ_INTEGER_ARG( amount );
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );

    mqo_string entropy = mqo_make_string( amount );

    mqo_read_random( random, entropy->data, amount );

    MQO_RESULT( mqo_vf_string( entropy ) );
MQO_END_PRIM( random_string )

MQO_BEGIN_PRIM( "random-quad", random_quad )
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );
    
    MQO_RESULT( mqo_vf_integer( mqo_random_long( random ) ) );
MQO_END_PRIM( random_quad )

MQO_BEGIN_PRIM( "random-integer", random_integer )
    REQ_INTEGER_ARG( min );
    REQ_INTEGER_ARG( max );
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );

    MQO_RESULT( mqo_vf_integer( mqo_random_integer( random, min, max ) ) );
MQO_END_PRIM( random_integer )

MQO_BEGIN_PRIM( "random-algorithm", random_algorithm )
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );

    MQO_RESULT( mqo_vf_string( mqo_string_fs( random->descr->name ) ) );
MQO_END_PRIM( random_algorithm )

MQO_BEGIN_PRIM( "export-random", export_random )
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );
    
    static char data[ 1024 ];
    unsigned long datalen = 1024;
    mqo_crypto_err( random->descr->pexport( data, &datalen, &( random->state ) ) );

    MQO_RESULT( mqo_vf_string( mqo_string_fm( data, datalen ) ) );
MQO_END_PRIM( export_random )

MQO_BEGIN_PRIM( "import-random", import_random )
    REQ_STRING_ARG( algorithm );
    REQ_STRING_ARG( data );
    NO_MORE_ARGS( );
    
    int id = find_prng( mqo_sf_string( algorithm ) );
    if( id == -1 ) mqo_errf( mqo_es_crypto, "s", "could not find prng" );

    struct ltc_prng_descriptor* descr = prng_descriptor + id;
    MQO_RESULT( mqo_vf_random( mqo_make_random( descr, mqo_sf_string( data ),
                                                mqo_string_length( data ) ) ) );
MQO_END_PRIM( import_random )

void mqo_bind_crypto_prims( ){
    MQO_BEGIN_PRIM_BINDS( );

    MQO_BIND_TYPE( random, nil )

    mqo_es_crypto = mqo_symbol_fs( "crypto" );

// TomCrypt is highly configurable -- we use the LTC symbols to determine what
// descriptors are available.

// Random Number Generators and Pseudo Random Number Generators
#ifdef YARROW
    assert( register_prng( &yarrow_desc ) >= 0 );
#endif
#ifdef RC4
    assert( register_prng( &rc4_desc ) >= 0 );
#endif
#ifdef FORTUNA
    assert( register_prng( &fortuna_desc ) >= 0 );
#endif
#ifdef SOBER128
    assert( register_prng( &sober128_desc ) >= 0 );
#endif
#if defined( SPRNG )
    assert( register_prng( &sprng_desc ) >= 0 );
#else
#   error "MOSVM requires that libtomcrypt provides SPRNG"
#endif

// MOSREF stretches rare entropy bytes by the use of a default RANDOM.
#if defined( FORTUNA )
    mqo_default_random = mqo_make_random( &fortuna_desc, NULL, 0 );
#elif defined( YARROW )
    mqo_default_random = mqo_make_random( &yarrow_desc, NULL, 0 );
#elif defined( SOBER128 )
    mqo_default_random = mqo_make_random( &sober128_desc, NULL, 0 );
#elif defined( RC4 )
    mqo_default_random = mqo_make_random( &rc4_desc, NULL, 0 );
#else
#  error "Could not find a PRNG suitable for mqo_default_random."
#endif
    mqo_symbol_fs( "*default-random*" )->value = 
        mqo_vf_random(  mqo_default_random );

    MQO_BIND_PRIM( make_random );
    MQO_BIND_PRIM( add_entropy );
    MQO_BIND_PRIM( random_string );
    MQO_BIND_PRIM( random_quad );
    MQO_BIND_PRIM( random_integer );
    MQO_BIND_PRIM( random_algorithm );
    MQO_BIND_PRIM( import_random );
    MQO_BIND_PRIM( export_random );

/*
    //TODO:
    MQO_BIND_PRIM( make_key );
    MQO_BIND_PRIM( public_key );
    MQO_BIND_PRIM( private_key );

    MQO_BIND_PRIM( import_key );
    MQO_BIND_PRIM( export_key );
    
    MQO_BIND_PRIM( keyq );

    MQO_BIND_PRIM( symmetric_keyq );
    MQO_BIND_PRIM( public_keyq );
    MQO_BIND_PRIM( private_keyq );

    //TODO: for block ciphers and rsa
    MQO_BIND_PRIM( encrypt );
    MQO_BIND_PRIM( decrypt );
    
    //TODO: for DH and ECDH systems
    MQO_BIND_PRIM( shared_key );

    //TODO: for hashes
    MQO_BIND_PRIM( hash );
*/
}
