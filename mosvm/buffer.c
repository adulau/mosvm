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

// The Buffer Type provides a expansible memory object that works well
// for I/O buffering.
/* MQO_BEGIN_TYPE( buffer )
      mqo_integer origin, length, capacity;
      void* data;
   MQO_END_TYPE( buffer ) */

mqo_buffer mqo_make_buffer( mqo_integer capacity ){
    mqo_buffer buffer = MQO_ALLOC( mqo_buffer, 0 );
    buffer->data = GC_malloc_atomic( capacity );
    buffer->capacity = capacity;
    return buffer;
}

void mqo_expand_buffer( mqo_buffer buffer, mqo_integer count ){
    mqo_integer space = (
        buffer->capacity - buffer->origin - buffer->length - - count 
    );

    if( space >= 0 ) return;
    if(( buffer->origin + space )>= 0 ){
        // We can just compress for it.
        memmove( buffer->data, 
                 buffer->data + buffer->origin, 
                 buffer->length );
        buffer->origin = 0;
    }else{
        // We expand enough to get the new write in, and add the capacity
        // of the old buffer for good measure.
        mqo_integer new_capacity = buffer->capacity + buffer->capacity - space;

        if( buffer->origin ){
            memmove( buffer->data, 
                     buffer->data + buffer->origin, 
                     buffer->length );
            buffer->origin = 0;
        };
        buffer->data = GC_realloc( buffer->data, new_capacity );
        buffer->capacity = new_capacity;
    }
}

void mqo_write_buffer( mqo_buffer buffer, const void* src, mqo_integer srclen ){
    memmove( buffer->data + buffer->origin + buffer->length, src, srclen );
    buffer->length += srclen;
}
void* mqo_buffer_head( mqo_buffer buffer ){
    return buffer->data + buffer->origin;
}

void mqo_skip_buffer( mqo_buffer buffer, mqo_integer offset ){
    assert( buffer->length >= offset );
    
    buffer->length -= offset;
    buffer->origin += offset;
}

void* mqo_read_buffer( mqo_buffer buffer, mqo_integer* r_count ){
    mqo_integer count = *r_count;
    void* data = mqo_buffer_head( buffer );
    if( count > buffer->length ) count = buffer->length;
    buffer->length -= count;
    buffer->origin += count;

    *r_count = count;
    return data;
}
void mqo_dump_buffer( mqo_buffer buffer ){
    mqo_write( "[buffer" );
    mqo_write( " capacity: " );
    mqo_writeint( buffer->capacity );
    mqo_write( " origin: " );
    mqo_writeint( buffer->origin );
    mqo_write( " length: " );
    mqo_writeint( buffer->length );
    mqo_write( "]\n" );
}

