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
(define reload #f)

(let ((cwd (getcwd))
      (cat '()))
 (set! import (lambda (key)
               (if (not (assoc key cat))
                (let ((path (string-append cwd "/" key ".scm")))
                 (set! cat (cons (cons key path) cat))
                 (reload key)))))
 (set! reload (lambda (key)
   (load (cdr (assoc key cat))))))

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

(import "lib/fakevm")

(define (guile-main args)
  (apply main (cdr args)))

(define (dict)
  (make-hash-table 31))

(define (dict-set! d k v)
  (hashq-set! d k v))

(define (dict-ref d k)
  (hashq-ref d k))

(define (dict-set? d k)
  (hashq-get-handle d k))

