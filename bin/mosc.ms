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
(import "lib/mosc")

(define (mosc/module name)
  (mosc name))

(define (mosc/program name)
  (if (string-ends-with? name ".ms")
    (set! name (substring name 0 (- (string-length name) 3))))
  (define exe (string-append name (if (string=? *platform* "winnt-x86")
                                    ".exe"
                                    "")))
  (print (string-append "Compiling " name " to " exe *line-sep*))
  (write-data-file exe (build-exe *platform* name)))

(define (mosc/run args)
  (cond 
    ((null? args)
     (print "mosc [-c] module")
     (print *line-sep*))
    ((string=? (car args) "-c")
     (mosc/program (cadr args)))
    (else (mosc/module (car args)))))

(define main
  (if *mosvm?* 
    (begin (mosc/run (argv)) (exit 0))
    mosc))

