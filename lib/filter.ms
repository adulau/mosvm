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

(module "lib/filter")

(export filter-output filter-input filter-port)

(define (filter-output filter port)
  (make-port (lambda (p c) (read port c))
             (lambda (p d) (write (filter d) port))
             (lambda (p) (close port))
             #f))

(define (filter-output (#t filter))
  (filter-output filter (current-output-port)))

(define (filter-input filter port)
  (make-port (lambda (p c) (filter (read port c)))
             (lambda (p d) (write d port))
             (lambda (p) (close port))
             #f))

(define (filter-input (#t filter))
  (filter-input filter (current-input-port)))

(define (filter-port inf outf port)
  (make-port (lambda (p c) (inf (read port c)))
             (lambda (p d) (write (outf d) port))
             (lambda (p) (close port))
             #f))

