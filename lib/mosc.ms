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

(import "lib/lib")
(import "lib/compile")
(import "lib/assemble")
(import "lib/optimize")
(import "lib/freeze")
(import "lib/eval")

(define (mosc module)
  (define src-file #f)
  (define dst-file #f)

  (cond
    ((string-ends-with? module ".ms")
     (set! src-file module)
     (set! module (string-head module (- (string-length module) 3))))
    ((string-ends-with? module ".scm")
     (set! src-file module)
     (set! module (string-head module (- (string-length module) 4))))
    (else
      (set! src-file (string-append module ".ms"))))

  (set! dst-file (string-append module ".mo"))

  (let ((data (read-lisp-file src-file)))
    (set! data (compile data))
    (set! data (optimize data))
    (set! data (assemble data))
    (set! data (freeze data))
    (set! dst-file (open-output-file dst-file))
    (write-data data dst-file)
    (close-output-port dst-file)))

(export mosc)
