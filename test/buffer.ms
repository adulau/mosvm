; Copyright (C) 2006, Ephemeral Security, LLC 
;  
; This library is free software; you can redistribute it and/or modify it  
; under the terms of the GNU Lesser General Public License as published by  
; the Free Software Foundation; either version 2.1 of the License, or (at  
; your option) any later version. 
;  
; This library is distributed in the hope that it will be useful, but WITHOUT  
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or  
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License  
; for more details. 
;  
; You should have received a copy of the GNU Lesser General Public License  
; along with this library; if not, write to the Free Software Foundation,  
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  
;  

(import "lib/test")

(enable-spot-tests)

(s: (make-buffer 1024))
(t: (buffer? _))
(t: (eq? (buffer-length _) 0))

(define b (make-buffer 1024))

(s: (read-buffer b))
(r: #f)

(s: (write-buffer b "hello"))
(r: #f)

(s: (read-buffer b))
(r: "hello")

(s: (read-buffer b))
(r: #f)

(s: (write-buffer-byte b 42))
(r: #f)

(s: (read-buffer-byte b))
(r: 42)

(s: (read-buffer-byte b))
(r: #f)

(s: (write-buffer-word b 1042))
(r: #f)

(s: (read-buffer-word b))
(r: 1042)

(s: (read-buffer-word b))
(r: #f)

(s: (write-buffer-quad b -1))
(r: #f)

(s: (read-buffer-quad b))
(r: -1)

(s: (read-buffer-quad b))
(r: #f)

(s: (write-buffer b "hello"))
(r: #f)

(s: (write-buffer b ", world"))
(r: #f)

(s: (read-buffer b))
(r: "hello, world")

(s: (write-buffer b "hello"))
(r: #f)

(s: (buffer->string b))
(r: "hello")

(s: (buffer->string b))
(r: "hello")

(define b (make-buffer 1))

(s: (write-buffer b "hello"))
(r: #f)

(s: (buffer->string b))
(r: "hello")

(s: (buffer->string b))
(r: "hello")

