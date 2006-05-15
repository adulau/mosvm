; Copyright (C) 2006, Ephemeral Security, LLC 
;  
; This library is free software; you can redistribute it and/or modify it  
; under the terms of the GNU Lesser General Public License as published by  
; the Free Software Foundation; either version 2.1 of the License, or (at  
; your option) any later version. 
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

(import "lib/test")
(import "lib/http-url")
(import "lib/http-server")

(enable-spot-tests)

(define req1 
  "GET /index.html HTTP/1.1\r\nHost: localhost:80\r\nAccept: */*\r\n\r\n")

(define reqp (open-input-string req1))
(define req (read-http-request reqp))

(s: (http-request? req))
(r: #t)

(s: (http-request-method req))
(r: "GET")

(define url (http-request-url req))

(s: (url-scheme url))
(r: "http")

(s: (url-auth url))
(r: #f)

(s: (url-path url))
(r: "/index.html")

(s: (http-request-version req))
(r: "HTTP/1.1")

(s: (http-request-header req "Host"))
(r: "localhost:80")

(s: (http-request-header req "Accept"))
(r: "*/*")

(define resp (open-output-string))
(write-http-response resp 200 "Peachy"
                     '("Content-Type: text/text")
                     "Life is peachy")

(s: (get-output-string resp))
(r: "HTTP/1.1 200 Peachy\r\nContent-Type: text/text\r\n\r\nLife is peachy")
