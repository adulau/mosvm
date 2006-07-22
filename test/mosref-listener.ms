; Copyright (C) 2006, Ephemeral Security, LLC
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(import "lib/test")

(enable-spot-tests)

(import "mosref/listener")

(define portno (random-integer 10000 30000))
(define s1 (make-mosref-listener portno))
(define k1 (wait s1))

(define c (tcp-connect "localhost" portno))
(s: (wait c))
(r: 'connect)

(send (random-string 32) c)
(s: (wait c))
(r: 'close)

(define c (tcp-connect "localhost" portno))
(s: (wait c))
(r: 'connect)

(send (random-string 16) c)
(s: (wait c))
(r: 'close)

(define c (tcp-connect "localhost" portno))
(s: (wait c))
(r: 'connect)

(send k1 c)
(s: (wait s1))
(t: (stream? _))

(send 'close c)

(define s1 (make-mosref-listener portno))
(define k1 (wait s1))
(define m1 (random-string 16))

(define c (tcp-connect "localhost" portno))
(s: (wait c))
(r: 'connect)

(send (string-append k1 m1) c)
(define s (wait s1))

(s: (wait s))
(r: m1)

(send k1 c)
(s: (wait s))
(r: k1)

(send 'close c)
(s: (wait s))
(r: 'close)

(send 'close s)

(exit)
