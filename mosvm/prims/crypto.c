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
#define REQ_AES_ARG( nm ) REQ_TYPED_ARG( nm, aes_key );

MQO_BEGIN_TYPE( random )
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

MQO_BEGIN_TYPE( aes_key )
    const struct ltc_cipher_descriptor *descr;
    symmetric_key key;
    mqo_integer keysize;
MQO_END_TYPE( aes_key )

void mqo_show_aes_key( mqo_aes_key key, mqo_word* ct ){
    mqo_write( "[aes-key " );
    mqo_writeint( key->keysize );
    mqo_write( "]" );
}

MQO_DEFN_TYPE2( "aes-key", aes_key )

mqo_integer mqo_crypto_err( mqo_integer result ){
    if( result != CRYPT_OK ){
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

mqo_aes_key mqo_make_aes_key( const void* keydata, int keylen, int keysize ){
    mqo_aes_key key = MQO_ALLOC( mqo_aes_key, 0 );
    key->descr = &aes_desc;
    key->keysize = keysize;
    mqo_crypto_err( aes_setup( keydata, keylen, 0, &( key->key ) ) );  
    return key;
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

MQO_BEGIN_PRIM( "make-aes-key", make_aes_key )
    REQ_INTEGER_ARG( size );
    OPT_VALUE_ARG( data );
    NO_MORE_ARGS( );
    
    mqo_aes_key key;

    if( size != 256 && size != 192 && size != 128 ){
        mqo_errf( mqo_es_args, "s", "key size must be either 256, 192 or 128" );
    }
    
    int len = size >> 3;

    if( ! has_data ){ data = mqo_vf_random( mqo_default_random ); }
    
    if( mqo_is_random( data ) ){
        static char keydata[64];
        mqo_read_random( mqo_random_fv( data ), keydata, len );
        key = mqo_make_aes_key( keydata, len, size );
    }else if(! mqo_is_string( data ) ){
        mqo_errf( mqo_es_args, "s", "data must be omitted, a string or"
                                    " a random" );
    }else if( mqo_string_length( mqo_string_fv( data ) ) < len ){
        mqo_errf( mqo_es_args, "s", "data is insufficient" );
    }else{
        key = mqo_make_aes_key( mqo_sf_string( mqo_string_fv( data ) ), 
                                len, size );
    }

    MQO_RESULT( mqo_vf_aes_key( key ) );
MQO_END_PRIM( make_aes_key )

MQO_BEGIN_PRIM( "aes-key?", aes_keyq )
    REQ_VALUE_ARG( value );
    NO_MORE_ARGS( );

    MQO_RESULT( mqo_vf_boolean( mqo_is_aes_key( value ) ) );
MQO_END_PRIM( aes_keyq )

MQO_BEGIN_PRIM( "aes-encrypt", aes_encrypt )
    REQ_AES_ARG( aes );
    REQ_STRING_ARG( plaintext );
    OPT_RANDOM_ARG( random );
    NO_MORE_ARGS( );

    int pslen = mqo_string_length( plaintext );
    if( pslen > 16 ){
        mqo_errf( mqo_es_args, "s" "plaintext cannot be longer than 16 bytes" );
    }
    
    static char ps[16];
    static char cs[16];

    memcpy( ps, mqo_sf_string( plaintext ), pslen );
    if( pslen < 16 ) mqo_read_random( random, ps + pslen, 16 - pslen );

    aes->descr->ecb_encrypt( ps, cs, &( aes->key ) );

    MQO_RESULT( mqo_vf_string( mqo_string_fm( cs, 16 ) ) );
MQO_END_PRIM( aes_encrypt )

MQO_BEGIN_PRIM( "aes-decrypt", aes_decrypt )
    REQ_AES_ARG( aes );
    REQ_STRING_ARG( ciphertext );
    NO_MORE_ARGS( );

    int cslen = mqo_string_length( ciphertext );
    if( cslen != 16 ){
        mqo_errf( mqo_es_args, "s" "ciphertext must be 16 bytes" );
    }
    
    static char ps[16];
    static char cs[16];

    memcpy( cs, mqo_sf_string( ciphertext ), cslen );

    aes->descr->ecb_decrypt( cs, ps, &( aes->key ) );

    MQO_RESULT( mqo_vf_string( mqo_string_fm( ps, 16 ) ) );
MQO_END_PRIM( aes_decrypt )

MQO_BEGIN_PRIM( "key-size", key_size )
    REQ_VALUE_ARG( key );
    NO_MORE_ARGS( );

    if( mqo_is_aes_key( key ) ){
        MQO_RESULT( mqo_vf_integer( mqo_aes_key_fv( key )->keysize ) );
    }else{
        mqo_errf( mqo_es_args, "s", "required encryption key" );
    }
MQO_END_PRIM( key_size )

MQO_BEGIN_PRIM( "key-block-size", key_block_size )
    REQ_VALUE_ARG( key );
    NO_MORE_ARGS( );

    if( mqo_is_aes_key( key ) ){
        MQO_RESULT( mqo_vf_integer( 16 ) );
    }else{
        mqo_errf( mqo_es_args, "s", "required encryption key" );
    }
MQO_END_PRIM( key_block_size )

MQO_BEGIN_PRIM( "xor-string", xor_string )
    REQ_STRING_ARG( string );
    REQ_STRING_ARG( mask );
    NO_MORE_ARGS( );
    
    mqo_integer strlen = mqo_string_length( string );
    if( strlen > mqo_string_length( mask ) ){
        mqo_errf( mqo_es_args, "s", 
                  "string length must be not be greater than mask length" );
    }

    mqo_string dst = mqo_make_string( strlen );
    mqo_integer i;

    for( i = 0; i < strlen; i ++ ){
        dst->data[ i ] = string->data[ i ] ^ mask->data[ i ];    
    }

    MQO_RESULT( mqo_vf_string( dst ) );
MQO_END_PRIM( xor_string )

MQO_BEGIN_PRIM( "base64-encode", base64_encode )
    REQ_STRING_ARG( plaintext )
    NO_MORE_ARGS( );

    unsigned long pslen = mqo_string_length( plaintext );
    unsigned long cslen = ( pslen << 2 ) / 3 + 5; 
    mqo_string ciphertext = mqo_make_string( cslen );
    mqo_crypto_err( base64_encode( mqo_sf_string( plaintext ), pslen,
                                   ciphertext->data, &cslen ) );
    ciphertext->length = cslen; 

    MQO_RESULT( mqo_vf_string( ciphertext ) );
MQO_END_PRIM( base64_encode )

MQO_BEGIN_PRIM( "base64-decode", base64_decode )
    REQ_STRING_ARG( ciphertext )
    NO_MORE_ARGS( );

    unsigned long cslen = mqo_string_length( ciphertext );
    unsigned long pslen = ( cslen * 3 ) >> 2; 
    mqo_string plaintext = mqo_make_string( pslen );
    mqo_crypto_err( base64_decode( mqo_sf_string( ciphertext ), cslen,
                                   plaintext->data, &pslen ) );
    plaintext->length = pslen; 

    MQO_RESULT( mqo_vf_string( plaintext ) );
MQO_END_PRIM( base64_decode )

void mqo_bind_crypto_prims( ){
    MQO_BEGIN_PRIM_BINDS( );

    MQO_BIND_TYPE( random, nil )
    MQO_BIND_TYPE2( "aes-key", aes_key, nil )

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

    register_cipher( &aes_desc );

    MQO_BIND_PRIM( make_aes_key ) // key-size random 
    MQO_BIND_PRIM( aes_keyq )     // value

    MQO_BIND_PRIM( aes_encrypt )  // aes plaintext random
    MQO_BIND_PRIM( aes_decrypt )  // aes ciphertext 
    MQO_BIND_PRIM( xor_string  )  // dst src
    MQO_BIND_PRIM( key_size )     // key
    MQO_BIND_PRIM( key_block_size ) // key

    MQO_BIND_PRIM( base64_encode )
    MQO_BIND_PRIM( base64_decode )
/*
    //TODO:
    MQO_BIND_PRIM( make_key );
    MQO_BIND_PRIM( public_key );
    MQO_BIND_PRIM( private_key );

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
