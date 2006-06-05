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

(module "lib/mailto-url")

(import "lib/url")
(import "lib/object")

(define-class mailto-url <object>
          (make-mailto-url user host)
          mailto-url?
              (user mailto-url-user)
          (host mailto-url-host))

(define *mailto-path-regex* (make-regex "(.*)@(.*)"))

(define (parse-mailto-url scheme auth path query frag)
  (define result (match-regex *mailto-path-regex* path))
  (if result
     (make-mailto-url (car result) (cadr result))
     (make-mailto-url path)))

(register-url-parser "mailto" parse-mailto-url)

(define (url-scheme (<mailto-url> url)) "mailto")
(define (url-auth   (<mailto-url> url)) #f)
(define (url-path   (<mailto-url> url))
  (if (mailto-url-host url)
    (string-append (mailto-url-user url) "@" (mailto-url-host url))
    (mailto-url-user url)))
(define (url-query  (<mailto-url> url)) #f)
(define (url-frag   (<mailto-url> url)) #f)

(export <mailto-url> make-mailto-url mailto-url? parse-mailto-url
        url-scheme url-auth url-path url-query url-frag)
