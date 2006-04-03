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

#ifndef MQO_BUFFER_H
#define MQO_BUFFER_H

#include "show.h"
#include "memory.h"

// The Buffer Type provides a expansible memory object that works well
// for I/O buffering.
MQO_BEGIN_TYPE( buffer )
    mqo_integer origin, length, capacity;
    void* data;
MQO_END_TYPE( buffer )

mqo_buffer mqo_make_buffer( mqo_integer capacity );
// Creates a buffer with the supplied initial capacity.

void mqo_expand_buffer( mqo_buffer buffer, mqo_integer data );
// Ensures that the buffer's capacity is sufficient for data bytes to be
// written to the buffer.

void mqo_write_buffer( mqo_buffer buffer, const void* src, mqo_integer srclen );
// Adds the supplied data to the buffer's tail. You should do an expansion 
// prior to using write.

void* mqo_buffer_head( mqo_buffer buffer );
// Returns a pointer to the current head of the buffer.

void mqo_skip_buffer( mqo_buffer buffer, mqo_integer offset );
// Advances the buffer head offset bytes, removing them from its current
// length.

void* mqo_read_buffer( mqo_buffer buffer, mqo_integer* count );
// Reads data from the buffer up to *count.  *count is updated with the
// actual number of bytes read, and the pointer returned points to the
// origin.  This pointer will be valid until the next buffer expansion or
// write operation.

void* mqo_read_line_buffer( mqo_buffer buffer, mqo_integer* count );
// Reads data from the buffer up to the next '\n' or '\r\n' separator, then
// advances the origin past the line and accompanying separator.  If a
// separator cannot be found, returns NULL.

static inline mqo_boolean mqo_buffer_empty( mqo_buffer buffer ){ 
    return buffer->length <= 0;
}
static inline mqo_integer mqo_buffer_length( mqo_buffer buffer ){
    return buffer->length;
}

#define mqo_show_buffer NULL
void mqo_dump_buffer( mqo_buffer buffer );

void mqo_flush_buffer( mqo_buffer buffer );
#endif
