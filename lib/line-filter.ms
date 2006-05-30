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

(module "lib/line-filter")

(define (line-filter in)
  (define out (make-channel))
  (define buf (make-string 80)) 

  (define (parse)
    (forever
      (define next (string-read-line! buf))
      (if next (send next out)
               (return))))
  
  (spawn (function (next-line)
            (until (closed? in)
               (define next (wait in))
               (when (string? next)
                 (string-append! buf next)
                 (parse)))
            (send buf out)
            (close out)))
  out)

(export line-filter)
;;; MOSVM2
