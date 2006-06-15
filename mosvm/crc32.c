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

// The classic CRC-32 from http://www.w3.org/TR/PNG-CRCAppendix.html, modified
// to behave itself in MOSVM.

#include "mosvm.h"
#include <stdlib.h>

/* Table of CRCs of all 8-bit messages. */
mqo_quad* mqo_crc_table = NULL;

/* Flag: has the table been computed? Initially false. */
int mqo_crc_table_computed = 0;

/* Make the table for a fast CRC. */
void mqo_init_crc_table(){
    mqo_quad c;
    int n, k;

    mqo_crc_table = malloc( 256 * sizeof( mqo_quad ) );

    for (n = 0; n < 256; n++) {
        c = (mqo_quad) n;
        for (k = 0; k < 8; k++) {
            if (c & 1)
                c = 0xedb88320L ^ (c >> 1);
            else
                c = c >> 1;
        }
        mqo_crc_table[n] = c;
    }
}

/* Update a running CRC with the bytes buf[0..len-1]--the CRC
   should be initialized to all 1's, and the transmitted value
   is the 1's complement of the final running CRC (see the
   mqo_crc() routine below)). */

mqo_quad mqo_update_crc( mqo_quad crc, unsigned char *buf, int len ){
    int n;

    for (n = 0; n < len; n++) {
        crc = mqo_crc_table[(crc ^ buf[n]) & 0xff] ^ (crc >> 8);
    }
    return crc;
}

/* Return the CRC of the bytes buf[0..len-1]. */
mqo_quad mqo_crc( unsigned char *buf, int len ){
    return mqo_update_crc(0xffffffffL, buf, len) ^ 0xffffffffL;
}

MQO_BEGIN_PRIM( "crc32", crc32 )
    REQ_STRING_ARG( data )
    NO_REST_ARGS( );

    INTEGER_RESULT( mqo_crc( (unsigned char*)mqo_sf_string( data ),
                             mqo_string_length( data ) ) );
MQO_END_PRIM( crc32 )

void mqo_init_crc32_subsystem( ){
    mqo_init_crc_table();
    MQO_BIND_PRIM( crc32 );
}
