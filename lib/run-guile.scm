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

(use-modules (srfi srfi-1)
             (srfi srfi-9))

(define import #f)

(let ((cwd (getcwd))
      ; These entries are provided by scheme but not mosvm
      (cat '("lib/iterate" "lib/record" "lib/port" "lib/string-port"
             "lib/file-port")))
 (set! import (lambda (key)
               (if (not (member key cat))
                (let ((path (string-append cwd "/" key ".ms")))
                 (set! cat (cons key cat))
                 (load path))))))

(define-macro (when test . stmt)
  `(if ,test (begin ,@stmt)))

(define-macro (unless test . stmt)
  `(if (not ,test) (begin ,@stmt)))

(define-macro (until test . stmt)
  `(let loop () (if (not ,test) 
                  (begin ,@stmt 
                         (loop)))))

(define-macro (while test . stmt)
  `(let loop () (if ,test 
                  (begin ,@stmt 
                         (loop)))))

(load "fakevm.scm")

(define (guile-main args)
  (apply main (cdr args)))

(define (set . items)
  (define s (make-hash-table 31))
  (for-each (lambda (v) (dict-set! s v #t))
            items)
  s)

(define (set-member? set item)
  (dict-ref set item))

(define (set-remove! set item)
  (dict-set! set item #f))

(define (set-add! set item)
  (dict-set! set item #t))

(define (dict . items)
  (define d (make-hash-table 31))
  (for-each (lambda (kv) (dict-set! d (car kv) (cdr kv)))
            items)
  d)

(define (dict-set! d k v)
  (hashq-set! d k v))

(define (dict-ref d k)
  (hashq-ref d k))

(define (dict-set? d k)
  (hashq-get-handle d k))

; Guile's stack is too small and conservative for lib/compile
(debug-set! stack 100000)

