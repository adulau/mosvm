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

; Expands on core/module

(module "lib/module")

(define *core-deps* (list "core/macro"
                          "core/config" 
                          "site/config"
                          "core/file"
                          "core/module"))

(define (parse-imports module)
  ;;; Returns a list of imported modules from a module.
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
    (filter is-import? (if (string? module)
                          (read-module-source module)
                          module)))

  (tc->list imports))

(define (parse-dependencies module)
  (define deps (make-tc))
  (define ign (set))
    
  (define (gen-module-deps mod)
    (unless (set-member? ign mod)
      (set-add! ign mod)
      (for-each (lambda (imp) (gen-module-deps imp))
                (parse-imports mod))
      (tc-append! deps mod)))

  (tc-splice! deps *core-deps*) 

  (gen-module-deps module)
  (tc->list deps))

(define (core-depencencies) *core-deps*)

(export parse-imports parse-dependencies core-depencencies)
