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

(s: (make-string 1024))
(t: (string? _))
(t: (eq? (string-length _) 0))

(define b (make-string 1024))

(s: (string-read! b))
(r: #f)

(s: (string-append! b "hello"))

(s: (string-read! b))
(r: "hello")

(s: (string-read! b))
(r: #f)

(s: (string-append-byte! b 42))

(s: (string-read-byte! b))
(r: 42)

(s: (string-read-byte! b))
(r: #f)

(s: (string-append-word! b 1042))

(s: (string-read-word! b))
(r: 1042)

(s: (string-read-word! b))
(r: #f)

(s: (string-append-quad! b -1))

(s: (string-read-quad! b))
(r: -1)

(s: (string-read-quad! b))
(r: #f)

(s: (string-append! b "hello"))

(s: (string-append! b ", world"))

(s: (string-read! b))
(r: "hello, world")

(s: (string-append! b "hello"))

(s: b)
(r: "hello")

(define b (make-string 1))

(s: (string-append! b "hello"))

(s: b)
(r: "hello")

