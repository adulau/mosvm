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

;; Implements a Cipher Feedback Mode state using a cipher, initialization
;; vector, and an encryption function.  

(module "lib/cfb")

(export <cfb> cfb? make-cfb cfb-encrypt cfb-decrypt key-size key-block-size)

(define-record-type cfb
                    (make-cfb-state key mask enc)
                    cfb?
                    (key cfb-key)
                    (mask cfb-mask set-cfb-mask!)
                    (enc cfb-enc))

(define (make-cfb key iv enc)
  (make-cfb-state key iv enc))

(define (next-cfb-mask cfb)
  (define mask ((cfb-enc cfb) (cfb-key cfb) (cfb-mask cfb)))
  (set-cfb-mask! cfb mask)
  mask)

(define (cfb-encrypt cfb plaintext)
  (xor-string plaintext (next-cfb-mask cfb)))

(define (cfb-decrypt cfb ciphertext)
  (xor-string ciphertext (next-cfb-mask cfb)))

(define (key-size (<cfb> cfb))
  (key-size (cfb-key cfb)))

(define (key-block-size (<cfb> cfb))
  (key-block-size (cfb-key cfb)))

