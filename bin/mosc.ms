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

; Given a source file, or the input port, and a target file, or the output
; port, compiles and outputs a frozen file.

(import "lib/build")

(define (main . args)
  (define exe-target #f)
  (define mods (make-tc))
  
  (define (parse-fail msg)
    (print (string-append "MOSC: " msg *line-sep*)))
  
  (define (parse-args args)
    (when (null? args) (return))
  
    (define arg (car args))
    (set! args (cdr args))
  
    (cond 
      ((string=? arg "-exe")
       (when (null? args) (parse-fail "Expected file name after -exe."))
       (set! exe-target (car args))
       (set! args (cdr args)))
      ((string-begins-with? arg "-")
       (parse-fail (string-append "Unrecognized option: " arg)))
      (else (tc-append! mods arg))) 
  
    (parse-args args))
  
  (parse-args args)

  (define old-build-module build-module)
  (set! build-module (lambda (item)
                       (print (string-append "BUILD: " item *line-sep*))
                       (old-build-module item)))
  (set! mods (tc->list mods))
  (set! mods (apply build-modules mods))
  
  (when exe-target
    ; This is pretty brute force..
    (write-data-file exe-target 
      (build-exe *platform* (map (lambda (item)
                                   (list 'import item))
                                 (filter (lambda (item)
                                           (not (string-begins-with? item 
                                                                     "core/")))
                                         mods))))))
  
