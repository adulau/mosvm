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

; Configure the doom channel..

(define (wait/doom . rest)
  (define doom (make-channel))
  (define time (timeout 1000 doom 
                  '(fail "Failed to complete tests in the allotted time")))
  (define data (error-on-fail (wait @rest doom)))
  (cancel-timeout time)
  data)

(define (expect channel value)
  (equal? value (wait/doom channel)))

(import "lib/filter")

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

