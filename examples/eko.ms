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

(import "lib/conn")

(define (eko-session port)
  (show "EKO: HELO")
  (newline)
  (until (closed? port)
    (define data (read port))
    (show "EKO: ")
    (show data)
    (newline)
    (if (eof-object? data)
      (close port)
      (write data port)))
  (show "EKO: BYE")
  (newline))

(define (eko portno)
  (spawn-tcp-server portno eko-session))
