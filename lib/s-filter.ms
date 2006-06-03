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

(module "lib/s-filter")
(import "lib/iterate")

(define (s-filter in)
  (define out (make-channel))
  (define buf (make-string 80)) 
  
  (define (parse)
    (guard (function (handle-parse-err err)
             (define key (error-key err))
             (define info (error-info err))
             (case key
               ((inc) (send "   ")
                      (string-append! buf *line-sep*))
               ((parse) (send (string-append "!! " (car info) *line-sep* ">> "))
                        (flush-string buf))
               (else (traceback err))))
       (send (string->exprs buf) out)
       (flush-string buf)))

  (spawn (function (s-reader)
            (forever
               (define next (wait in))

               (when (eq? next 'close)
                 (send next out)
                 (return))

               (when (string? next)
                 (string-append! buf next)
                 (parse)))))
  out)

(export s-filter)
;;; MOSVM2
