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

(define m "The quick brown fox jumped over the lazy dog")
(s: (base64-encode m))
(r: "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2c=")
(t: (string=? (base64-decode _) m))

(s: (make-aes-key 256))
(t: (aes-key? _))
(t: (eq? (key-size _) 256))
(t: (eq? (key-block-size _) 16))

(define k (make-aes-key 256 "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk"))
(define p "the quick brown ")
(define c "+QMup9bKGCBpCJb0552tYw==")

(s: (base64-encode (aes-encrypt k p)))
(r: c)

(s: (aes-decrypt k (base64-decode c)))
(r: p)

(s: (xor-string "alpha" "maskm"))
(t: (= (string-length _) 5))
(t: (not (string=? _ "alpha")))
(t: (string=? (xor-string _ "maskm") "alpha"))

(s: (make-ecdh-key 256))
(t: (ecdh-key? _))
(t: (ecdh-private-key? _))
(t: (not (ecdh-public-key? _)))

(define c (make-ecdh-key 256))
(define d (make-ecdh-key 256))

(s: (import-ecdh (export-private-ecdh c)))
(t: (ecdh-key? _))
(t: (ecdh-private-key? _))
(t: (not (ecdh-public-key? _)))

(s: (import-ecdh (export-public-ecdh c)))
(t: (ecdh-key? _))
(t: (ecdh-public-key? _))
(t: (not (ecdh-private-key? _)))

(define cp (import-ecdh (export-public-ecdh c)))
(define dp (import-ecdh (export-public-ecdh d)))
(define cq c)
(define dq d)

(s: (ecdh-shared-secret cq dp))
(r: (ecdh-shared-secret dq cp))
(t: (string? _))

