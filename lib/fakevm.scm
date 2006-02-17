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
;  

; Simulates functionality required by the MOSVM compiler that would
; normally be provided by MOSVM.

(define *mosvm?* #f)

(define (show x . v) (write x))

(define (main . args) 
  (if (> *spot-ect* 0)
    (begin 
      (display "Failed tests: ")
      (display *spot-ect*)
      (newline))

      (exit *spot-ect*)))

(define (error . rest)
  (write rest)(newline)(wrong))

(define (cons* . args)
  (if (null? (cdr args))
      (car args)
      (cons (car args) 
            (apply cons* (cdr args)))))          

(define (make-tc) (cons '() '()))

(define (tc-append! tc item)
  (set! item (cons item '()))
  (if (null? (car tc)) 
    (set-car! tc item)
    (set-cdr! (cdr tc) item))
  (set-cdr! tc item)
  tc)

(define (tc-prepend! tc item)
  (set! item (cons item (car tc)))
  (if (null? (cdr tc))
    (set-cdr! tc item))
  (set-car! tc item)
  tc)

(define (tc-next! tc)
  (when (tc-empty? tc) (error 'vm "tc is empty"))
  (let ((item (car tc)))
	(set-car! tc (cdr item))
	(if (null? (cdr item))
	  (set-cdr! tc '()))
	(car item)))

(define (tc-empty? tc)
  (null? (car tc)))

(define (tc-splice! tc list)
  (for-each (lambda (x) (tc-append! tc x))
			list))

(define tc->list car)
(define tc-head car)
(define tc-tail cdr)

(define (tc? tc) (pair? tc))

(define-record-type 
  <program>
  (make-program size body)
  program?
  (size program-length)
  (body program-body))

(let ((super make-program))
  (set! make-program (lambda (sz) 
                       (let ((v (make-vector sz)))
                         (let loop ((ix 0))
                           (unless (= ix sz)
                             (vector-set! v ix (make-instruction #f #f))
                             (loop (+ ix 1))))
                         (super sz v)))))

(define (program-ref pg ofs) 
  (unless (program? pg) (error 'type-mismatch pg))
  (unless (< ofs (program-length pg)) (error 'index-overflow pg ofs))
  (vector-ref (program-body pg) ofs))

(define-record-type 
  <instruction>
  (make-instruction code args) ;;; Not a mosvm primitive.
  instruction?
  (code instruction-code set-instruction-code!)
  (value instruction-value set-instruction-value!)
  (word1 instruction-word1 set-instruction-word1!)
  (word2 instruction-word2 set-instruction-word2!)
  (symbol instruction-symbol set-instruction-symbol!))

(define (set-program-code-at! pg ofs code)
  (set-instruction-code! (program-ref pg ofs) code))

(define (program-code-at pg ofs) 
  (instruction-code (program-ref pg ofs)))
(define (set-program-value-at! pg ofs value)
  (set-instruction-value! (program-ref pg ofs) value))
(define (program-value-at pg ofs) 
  (instruction-value (program-ref pg ofs)))
(define (set-program-word1-at! pg ofs word1)
  (set-instruction-word1! (program-ref pg ofs) word1))
(define (program-word1-at pg ofs) 
  (instruction-word1 (program-ref pg ofs)))
(define (set-program-word2-at! pg ofs word2)
  (set-instruction-word2! (program-ref pg ofs) word2))
(define (program-word2-at pg ofs) 
  (instruction-word2 (program-ref pg ofs)))
(define (set-program-symbol-at! pg ofs symbol)
  (set-instruction-symbol! (program-ref pg ofs) symbol))
(define (program-symbol-at pg ofs) 
  (instruction-symbol (program-ref pg ofs)))

(define (map-car . args) (apply map car args))
(define (map-cdr . args) (apply map cdr args))

(define (write-byte byte port)
  (write-char (integer->char byte) port))

(define (last-item list)
  (car (last-pair list)))

(define (write-word word port)
  ; writes a word in network byte order. (MSB)
  (write-byte (quotient word 256) port)
  (write-byte (remainder word 256) port))

(define (write-quad quad port)
  ; writes a quad in network word order. (MSB)
  (write-word (quotient quad 65536) port)
  (write-word (remainder quad 65536) port))

(define (read-all-loop port tc)
  (let ((item (read port)))
    (if (eof-object? item)
      (tc->list tc)
      (begin (tc-append! tc item)
             (read-all-loop port tc)))))

(define (read-all port)
  (read-all-loop port (make-tc)))

(define (module . dont-care) #f) ;This is used by MOSVM to ensure built-in
                                 ;modules are registered.

(define-macro (export . don't-car) 1) ;This is used by MOSVM to identify
                                      ;exported identifiers.
