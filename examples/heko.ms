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

(import "lib/http-server")

(define (heko-session req)
  (define method (http-request-method req))
  (define url (http-request-url req))
  (unless (string=? method "GET")
    (error 'http "Method not supported" 400))
  (write-http-response req 200 "OK" 
                       '("Content-Type: text/plain") 
                       (url-path url)))

(define (heko portno)
  (spawn-http-server portno heko-session))

