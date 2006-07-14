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

(define (wait/doom doom)
  (define time (timeout 5000 doom 
                  '(fail "Failed to complete tests in the allotted time")))
  (define data (error-on-fail (wait doom)))
  (cancel-timeout time)
  data)

(define (expect channel value)
  (equal? value (wait/doom channel)))

(import "lib/filter")

;; Our identity filter..

(define-filter (identity-filter)
    (forever
      (send (wait in) out)))

;; Linking in to in..
(define in (make-channel))
(define mid (input-chain in (identity-filter)))
(define out (input-chain mid (identity-filter)))

(s: (send "test" in))
(t: (expect out "test"))

;; Test Block-Filter Module
(import "lib/block-filter")

;; Test block-split-filter
(define in (make-channel))
(define out (input-chain in (block-split-filter 8)))

(s: (send (copy-string "alpha") in))
(t: (expect out "\0\0\0\5alph"))

(s: (wait/doom out))
(t: (string-begins-with? _ "a"))
(t: (= (string-length _) 8))

(s: (send 'foo in))
(t: (expect out 'foo))

;; Test block-merge-filter

(define in (make-channel))
(define out (input-chain in (block-merge-filter 8)))

(s: (send (copy-string "\0\0\0\5alph") in)
    (send (copy-string "a\1\2\3\4\5\6\7") in))
(t: (expect out "alpha"))

(s: (send 'foo in))
(t: (expect out 'foo))

(s: (send (copy-string "\0\0\0\4beta") in))
(t: (expect out "beta"))

(s: (send 'foo in))
(t: (expect out 'foo))

; Test Crypto-Filter Module (and Copy-Filter)
(import "lib/cfb")
(import "lib/crypto-filter")
(import "lib/copy-filter")

(define iv "themagicinitvect")
(define ky (make-aes-key 256))

(define tx (make-cfb ky iv aes-encrypt))
(define rx (make-cfb ky iv aes-encrypt))

(define in (make-channel))
(define out (input-chain in 
                         (copy-filter)
                         (encrypt-filter (lambda (block) 
                                           (cfb-encrypt tx block)))
                         (decrypt-filter (lambda (block) 
                                           (cfb-decrypt rx block)))))

(define m1 "transmission-001")
(define m2 "now is the time for all good people")
(define m3 "abc")

(s: (send iv in))
(t: (expect out iv))

(s: (send 'foo in))
(t: (expect out 'foo))

(define in (make-channel))
(define out (input-chain in 
                         (copy-filter)
                         ;(trace-filter "plaintext")
                         (block-split-filter (key-block-size tx))
                         (encrypt-filter (lambda (block) 
                                           (cfb-encrypt tx block)))
                         ;(trace-filter "ciphertext" )
                         (decrypt-filter (lambda (block) 
                                           (cfb-decrypt rx block)))
                         (block-merge-filter (key-block-size rx))))

(s: (send m1 in))
(t: (expect out m1))

(s: (send m2 in))
(t: (expect out m2))

(s: (send m3 in))
(t: (expect out m3))

(s: (send m1 in)
    (send m2 in)
    (send m3 in))

(t: (expect out m1))
(t: (expect out m2))
(t: (expect out m3))

(import "lib/checksum-filter")

(define in (make-channel))
(define out (input-chain in 
                         (copy-filter)
                         (prepend-checksum-filter crc32)
                         (check-checksum-filter crc32)))

(s: (send m1 in))
(t: (expect out m1))

(s: (send m2 in))
(t: (expect out m2))

(s: (send m3 in))
(t: (expect out m3))

(s: (send m1 in)
    (send m2 in)
    (send m3 in))

(t: (expect out m1))
(t: (expect out m2))
(t: (expect out m3))

; This is the transmission flow for MOSREF.

(define iv "themagicinitvect")
(define ky (make-aes-key 256))

(define tx (make-cfb ky iv aes-encrypt))
(define rx (make-cfb ky iv aes-encrypt))

(define in (make-channel))
(define out (input-chain in 
                         (copy-filter)
                         ;(trace-filter "plaintext")
                         (prepend-checksum-filter crc32)
                         (block-split-filter (key-block-size tx))
                         (encrypt-filter (lambda (block) 
                                           (cfb-encrypt tx block)))
                         ;(trace-filter "ciphertext" )
                         (decrypt-filter (lambda (block) 
                                           (cfb-decrypt rx block)))
                         (block-merge-filter (key-block-size rx))
                         (check-checksum-filter crc32)))

(s: (send m1 in))
(t: (expect out m1))

(s: (send m2 in))
(t: (expect out m2))

(s: (send m3 in))
(t: (expect out m3))

(s: (send m1 in)
    (send m2 in)
    (send m3 in))

(t: (expect out m1))
(t: (expect out m2))
(t: (expect out m3))

