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

#ifndef MQO_THAW_H
#define MQO_THAW_H 1

#define MQO_THAW_NIL	    0
#define MQO_THAW_T	    1
#define MQO_THAW_F	    2
#define MQO_THAW_NEGINT	    3
#define MQO_THAW_POSINT	    4
#define MQO_THAW_PAIR	    5
#define MQO_THAW_STRING	    6
#define MQO_THAW_SYMBOL     7
#define MQO_THAW_VECTOR     8
#define MQO_THAW_PROGRAM    9

#include <stdio.h>

mqo_pair mqo_thaw_memory( const char* data, size_t len );

// Given a region of memory, mqo_thaw will attempt to reconstruct a lisp value
// that has been serialized to a buffer.  If the reconstruction is successful,
// a pair will be returned containing ( true . first-value ) is returned,
// otherwise the result shall be ( false . error-message ).
//
// buffer    := count root record+
//   The count indicates the number of records contained by the codex.
//
//   The root index indicates the record that should be returned as the root
//   value.
//
// record-ct := word
//   There must be at least one record, and no more than 16384 records.
//
// record    := 00 | 01 | 02 ( ( 03 | 04 ) integer ) | ( 06 pair ) | ( ( 06 | 07 ) string )

//   a 00 indicates nil
//   a 01 indicates true
//   a 02 indicates false
//   a 03 indicates a negative integer
//   a 04 indicates a positive integer
//   a 05 indicates a pair
//   a 06 indicates a string
//   a 07 indicates a symbol
//   a 07 indicates a vector
//
// integer   := long
//   integers are encoded as their absolute values -- the sign is carried by
//   the type field.
//
// pair      := word word
//   pairs encode an absolute index to their value records.
// 
// vector    := word word ...
//   vectors encode their length, then an absolute index to each of their value
//   records.
// By convention, record 00 should be nil, 01 should be true, and 02 should
// be false, but this is not required.

mqo_pair mqo_thaw_file( FILE* file );
// As mqo_thaw_memory, but loads into memory from the current file position.

mqo_pair mqo_fthaw( const char* path );
// As mqo_thaw_memory, but loads into memory from supplied path.

mqo_pair mqo_thaw_tail( const char* path );
// As with mqo_fthaw, but thaws a list of frozen objects from the supplied path
// with the assumption that they have been "glued" to the path, tail-first.

#endif

