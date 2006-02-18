1101; Copyright (C) 2006, Ephemeral Security, LLC 
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

(module "lib/manifest")

(define (read-module-src path)
  (define f #f)
  (define d #f)
  (guard 
    (lambda (e) 
      (set! f (open-file-descr (string-append path ".scm") "r")))
    (set! f (open-file-descr (string-append path ".ms") "r")))
  (unless f (error 'import "cannot find source code for module" path))
  (set! d (string->exprs (read-file-all f)))
  (close-descr f)
  d)
(export read-module-src)  
(define (module-imports module)
  (define imports (make-tc))

  (define (is-import? expr)
    (and (pair? expr)
         (= (length expr) 2)
         (eq? (car expr) 'import)))

  (define (add-import expr)
    (define module (cadr expr))
    (unless (memq module (tc->list imports))
      (tc-append! imports module)))

  (for-each 
    add-import
    (filter is-import? (read-module-src module)))

  (tc->list imports))

(define (module-dependencies module)
  (define deps (make-tc))
  (define ign (set))
  (define (gen-module-deps mod)
    (unless (set-member? ign mod)
      (set-add! ign mod)
      (for-each (lambda (imp) (gen-module-deps imp))
                (module-imports mod))
      (tc-append! deps mod)))
  (gen-module-deps module)
  (tc->list deps))

(export module-imports module-dependencies)
