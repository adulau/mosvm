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

(import "lib/compile")
(import "lib/optimize")

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

  ;; Only MOSVM can produce VM3 object files.

  (if *mosvm?*
    (set! dst-file (string-append module ".mo"))
    (set! dst-file (string-append module ".ma")))

  (let ((data (read-lisp-file src-file)))
    (set! data (compile data))
    (set! data (optimize data))

    (when *mosvm?*
      (set! data (assemble data))
      (set! data (freeze data)))
    (set! dst-file (open-output-file dst-file))
    (if *mosvm?*
      (write-data data dst-file)
      (for-each (lambda (item)
                  (write item dst-file)
                  (newline dst-file))
                data))
    (close-output-port dst-file)))

(export mosc)
