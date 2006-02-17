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

(module "lib/lib")

(define write-data
  (if *mosvm?*
    write
    display))

(define *branch-index* 0)

(define (req-arg args index message)
  (if (< index (length args)) (list-ref args index)
    (error message)))

(define (opt-arg args index default)
  (if (< index (length args)) (list-ref args index)
    default))

(define (reset-branch-index)
  (set! *branch-index* 0))

(define (make-branch-symbol root) 
  (set! *branch-index* (+ *branch-index* 1))
  (string->symbol (string-append (symbol->string root) "-" (number->string *branch-index*))))

(define *op-table*
  (list (vector 'stop  0 'none)
        (vector 'ldc   1 'value)
        (vector 'ldg   2 'symbol)
        (vector 'ldb   3 'env)
        (vector 'ldf   4 'addr)
        (vector 'stg   5 'symbol)
        (vector 'stb   6 'env)
        (vector 'jmp   7 'addr)
        (vector 'jf    8 'addr) 
        (vector 'call  9 'none)
        (vector 'tail 10 'none) 
        (vector 'retn 11 'none) 
        (vector 'usen 12 'env)
        (vector 'usea 13 'env)
        (vector 'ldu  14 'none) 
        (vector 'drop 15 'none)
        (vector 'gar  16 'addr)
        (vector 'rag  17 'none)
        (vector 'jt   18 'addr)
        (vector 'copy 19 'none)))

(define *ops-by-name* (dict))
(for-each (lambda (row) (dict-set! *ops-by-name* (vector-ref row 0) row))
          *op-table*)

(define *ops-by-code* (dict))
(for-each (lambda (row) (dict-set! *ops-by-code* (vector-ref row 1) row))
          *op-table*)

(define *op-count* (length *op-table*))

(define (find-op-row-by-name name)
  (dict-ref *ops-by-name* name))

(define (find-op-row-by-code code)
  (dict-ref *ops-by-code* code))

(define (unkink l)
  (cond 
    ((null? l) l)
    ((pair? l)
     (let ((tc (make-tc)))
       (while (and (pair? l) 
                   (not (null? l)))
              (tc-append! tc (car l))
              (set! l (cdr l)))
       (unless (null? l) (tc-append! tc l))
       (tc->list tc)))
    (else l)))

(define (make-symbol . items)
  (string->symbol 
    (apply string-append 
           (map (lambda (item) 
                  (cond ((string? item) item)
                        ;((char? item) (string item))
                        ((symbol? item) (symbol->string item))))
                items))))

(define (circle v) 
  (let ((c (cons v #f)))
    (set-cdr! c c)
    c))

(define symbol-starts-with?
  (if *mosvm?*
    (lambda (symbol char)
      (eq? (string-ref (symbol->string symbol) 0) char))
    (lambda (symbol char)
      (eq? (string-ref (symbol->string symbol) 0) 
           (integer->char char)))))

(export req-arg opt-arg reset-branch-index make-branch-symbol
        find-op-row-by-name find-op-row-by-code unkink make-symbol
        circle symbol-starts-with? write-data)
