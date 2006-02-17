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

(module "lib/assemble")
(import "lib/lib")
(export assemble)

(define-record-type <assembler>
  (make-assembler size index program addrs labels)
  assembler?
  (size assembler-size)
  (index assembler-index set-assembler-index!)
  (program assembler-program)
  (addrs  assembler-addrs set-assembler-addrs!)
  (labels assembler-labels set-assembler-labels!))

(let ((super make-assembler))
  (set! make-assembler (lambda (size)
                         (super size 0 (make-program size) '() '()))))

(define assembler->program assembler-program)

(define (add-assembler-label! assembler label)
  (set-assembler-labels! 
    assembler
    (cons (cons label
                (assembler-index assembler))
          (assembler-labels assembler))))

(define (add-assembler-addr! assembler label)
  (set-assembler-addrs! 
    assembler
    (cons (cons label
                (assembler-index assembler))
          (assembler-addrs assembler))))

(define (find-assembler-label assembler label)
  (assq label (assembler-labels assembler)))

(define (patch-assembler-addr! assembler index) 
  (set-program-word1-at! (assembler-program assembler)
                         index
                         (assembler-index assembler)))

(define (resolve-assembler-addr! assembler key)
  (let ((label (assq key (assembler-labels assembler))))
    (if label
      (set-program-word1-at! (assembler-program assembler)
                                (assembler-index assembler)
                                (cdr label))
      (add-assembler-addr! assembler key))))
        
(define (assemble-no-args assembler args)
  (unless (eq? (length args) 0)
    (error 'asm "expected no arguments" args)))

(define (assemble-value-arg assembler args)
  (unless (eq? (length args) 1)
    (error 'asm "expected one value argument" args))
  (set-program-value-at! (assembler-program assembler)
                             (assembler-index assembler)
                             (car args)))

(define (assemble-env-args assembler args)
  (unless (and (eq? (length args) 2)
               (integer? (car args))
               (integer? (cadr args)))
    (error 'asm "expected two integer arguments" args))
  (let ((program (assembler-program assembler))
        (index (assembler-index assembler)))
    (set-program-word1-at! program index (car args))
    (set-program-word2-at! program index (cadr args))))


(define (assemble-symbol-arg assembler args)
  (unless (and (eq? (length args) 1)
               (symbol? (car args)))
    (error 'asm "expected one symbol argument" args))
  (set-program-symbol-at! (assembler-program assembler)
                              (assembler-index assembler)
                              (car args)))

(define (assemble-addr-arg assembler args)
  (unless (and (eq? (length args) 1)
               (symbol? (car args)))
    (error 'asm "expected label symbol argument" args))
  (resolve-assembler-addr! assembler (car args)))

(define (assemble-label assembler key)
  (when (find-assembler-label assembler key) 
        (error 'asm "The following label was redefined:" key))
  (set-assembler-addrs! 
    assembler
    (filter! (lambda (addr)
               (if (eq? (car addr) key)
                 (begin (patch-assembler-addr! assembler (cdr addr))
                        #f)
                 #t))
             (assembler-addrs assembler)))
  (add-assembler-label! assembler key))

(define (assemble-instruction assembler instruction)
  ;(show (list 'assemble-instruction instruction))
  ;(newline) 

  (let ((name (car instruction))
        (args (cdr instruction)))
   (let ((len (length args))
         (row (find-op-row-by-name name)))
     (set-program-code-at! (assembler-program assembler)
                           (assembler-index assembler)
                           (vector-ref row 1))
     ((case (vector-ref row 2)
        ((none)   assemble-no-args)
        ((value)  assemble-value-arg)
        ((env)    assemble-env-args)
        ((symbol) assemble-symbol-arg)
        ((addr)   assemble-addr-arg)
        (else (error 'asm "unrecognized instruction type")))
      assembler args)
     (set-assembler-index! assembler (+ (assembler-index assembler) 1)))))

(define (pair-count list)
  (fold (lambda (x c) (if (pair? x) (+ c 1) c))
		0 list))

(define (assemble source)
  (let ((assembler (make-assembler (pair-count source))))
    (for-each (lambda (stmt)
                (cond 
                  ((pair? stmt)   (assemble-instruction assembler stmt))
                  ((symbol? stmt) (assemble-label assembler stmt))
                  (else (error 'asm 
                               "assembler statements should be labels or lists"
                               stmt))))
              source)
    (unless (null? (assembler-addrs assembler))
      (error 'asm "unresolved label references:" (assembler-addrs assembler)))

    (assembler->program assembler)))

; (define a (assemble '()))
; (define b (assemble '((stop))))
; (define c (assemble '((ldf lam-1) (stop) lam-1 (ldg 1) (retn))))
