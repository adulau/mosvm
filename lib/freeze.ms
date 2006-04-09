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

(module "lib/freeze")
(import "lib/lib")
(import "lib/file-port")
(import "lib/iterate")

(define (program-values program)
  (define inv '())
  (define size (program-length program))
  (define index 0)
  (while (< index size)
    (let ((code (program-code-at program index)))
      (case (vector-ref (find-op-row-by-code code) 2)
        ((symbol) 
         (set! inv (cons (program-symbol-at program index) inv)))
        ((value)  
         (set! inv (cons (program-value-at program index) inv))))
    (set! index (+ index 1))))
  inv) 

(define (freeze value . args)
  (let ((port-arg (opt-arg args 0 #f)))
    (let ((port (if port-arg port-arg 
                             (open-output-string))))
      (encode-inventory (make-inventory value) port)
      (if (not port-arg)
        (get-output-string port)))))

(define (make-inventory value)
  ; Given an atom, vector, or list, returns a list containing one of each
  ; value referenced by that object.
  ;
  ; The seed value will be the last item in the returned list; circular lists
  ; are fine with this function.

  (define rest (list value))

  (define index (dict))
  (define items (make-tc))
  (define count 0)

  (define item #f)

  (define (add-to-inv item)
    (tc-append! items item)
    (dict-set! index item count)
    (set! count (+ count 1)))

  (until (null? rest)
    (set! item (car rest))
    (set! rest (cdr rest))
    (if (not (dict-set? index item))
      (begin
        (add-to-inv item)
        (cond ((program? item)
               (set! rest (append (program-values item) rest)))
              ((vector? item) ;TODO: Add vector->list to core.
               (set! rest (append (vector->list item) rest)))
              ((null? item))
              ((pair? item) 
               (set! rest (cons (car item) (cons (cdr item) rest))))))))
  (vector count index (tc->list items) value))

(define (encode-inventory inv port) 
  (define count (vector-ref inv 0))
  (define index (vector-ref inv 1))
  (define items (vector-ref inv 2))
  (define root  (vector-ref inv 3))
 
  (when #f
  (when *mosvm?* 
    (show "Encoding ")
    (show inv)
    (show "...")
    (newline))

  (when *mosvm?*
     (dump-dict index))

  (when *mosvm?*
     (show "Count is ")
     (show count)
     (newline)
     (show "Root is ")
     (show root)
     (newline)
     (show "Root Offset is ")
     (show (dict-ref index root))
     (newline)))

  (write-word count port) ; Record count
  (write-word (dict-ref index root) port) ; The Root offset.
   
  (for-each (lambda (item) (encode-record item index port))
            items))

(define (encode-record value index port)
  ((cond ((null? value) encode-null-record)
         ((program? value) encode-program-record)
         ((pair? value) encode-pair-record)
         ((vector? value) encode-vector-record)
         ((string? value) encode-string-record)
         ((symbol? value) encode-symbol-record)
         ((integer? value) encode-integer-record)
         ((eq? value #t) encode-bool-record)
         ((eq? value #f) encode-bool-record)
         (else (error 'enc "cannot encode a value of this type." value)))
   value index port))

(define (encode-null-record value index port) 
  (write-byte 00 port))

(define (encode-pair-record value index port) 
  (write-byte 05 port)
  (write-word (dict-ref index (car value)) port)
  (write-word (dict-ref index (cdr value)) port))
  
(define (encode-string-record value index port) 
  (write-byte 06 port)
  (write-word (string-length value) port)
  (write-data value port))

(define (encode-symbol-record value index port) 
  (let ((v (symbol->string value)))
    (write-byte 07 port)
    (write-word (string-length v) port)
    (write-data v port)))

(define (encode-integer-record value index port) 
  (write-byte (if (< value 0) 03 04) port)
  (write-quad (abs value) port))
  
(define (encode-bool-record value index port)
  (write-byte (if value 01 02) port))

(define (encode-vector-record value index port) 
  (write-byte 08 port)
  (write-word (vector-length value) port)
  (for-each (lambda (item) (write-word (dict-ref index item) port))
            (vector->list value)))

(define (encode-program-record value index port)
  (define ofs 0)
  (define size (program-length value))

  (write-byte 09 port)
  (write-word size port)

  (while (< ofs size)
    (let ((code (program-code-at value ofs)))
      (write-byte code port) 
      (case (vector-ref (find-op-row-by-code code) 2)
        ((symbol) (write-word (dict-ref index (program-symbol-at value ofs)) 
                               port))
        ((value)  (write-word (dict-ref index (program-value-at value ofs))
                               port))
        ((addr) (write-word (program-word1-at value ofs) port))
        ((env)  (write-word (program-word1-at value ofs) port)
                (write-word (program-word2-at value ofs) port))))
    (set! ofs (+ ofs 1))))

(export freeze) 

