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

(module "mosref/format")

(define (format-ipv4 i)
  (define (ub i)
    (if (< i 0) (+ i 256) i))

  (define buf (make-string 16))
  (string-append! buf (format (ub (>> i 24))))
  (string-append! buf ".")
  (set! i (& i $FFFFFF))
  (string-append! buf (format (>> i 16)))
  (string-append! buf ".")
  (set! i (& i $FFFF))
  (string-append! buf (format (>> i 8)))
  (string-append! buf ".")
  (set! i (& i $FF))
  (string-append! buf (format i))
  buf)

(export format-ipv4)
