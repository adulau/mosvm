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
(import "lib/port")

;(import "lib/eval") Deferred due to cyclic dependencies.

(define make-procedure
  (if *mosvm?*
    (lambda (args body) (eval `(lambda ,args ,@body)))
    (lambda (args body) (primitive-eval `(lambda ,args ,@body)))))

(export make-procedure)

(define write-data
  (if *mosvm?*
    write
    display))

(define *branch-index* 0)

(define (reset-branch-index)
  (set! *branch-index* 0))

(define (make-branch-symbol root) 
  (set! *branch-index* (+ *branch-index* 1))
  (string->symbol (string-append (symbol->string root) "-" (number->string *branch-index*))))

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

(define read-lisp-file
  (if *mosvm?*
    (lambda (path)
      (define file (open-file-descr path "r"))
      (define data (read-descr-all file))
      (close-descr file)
      (string->exprs data))
    (lambda (path)
      (let ((f (open-input-file path)))
        (let ((d (read-all f)))
          (close-input-port f)
          d)))))

(export reset-branch-index make-branch-symbol
        unkink make-symbol
        circle symbol-starts-with? write-data 
        read-lisp-file)

