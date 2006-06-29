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


(module "mosref/prod-http")
(import "mosref/prod")

;; A simple get root query will generally gather all of the headers required to classify
;; a HTTP server.

(tcp-stimulus http-get-root 
              ports: 80 81 82 8000 8081 8888
              "GET / HTTP/1.0\r\n\r\n")

;; HTTP-v1, the plain white bread of the innerweb
(tcp-response http-v1
              to: http-get-root
              head: "HTTP/1")

;; There are very few http-v0 servers alive today..
(tcp-response http-v0
              isnt: http-v1
              to: http-get-root
              head: "HTTP/0")

;; TODO: response checks for HTTP/1.1 and HTTP/1.0 for boutique http servers.

(tcp-response http-apache
              to: http-get-root
              is: http-v1
              frag: "\nServer: Apache/")

(tcp-response http-apache-v1
              to: http-get-root
              is: http-apache
              frag: "\nServer: Apache/1")

(tcp-response http-apache-v2
              to: http-get-root
              is: http-apache
              frag: "\nServer: Apache/2")

(tcp-response http-iis
              to: http-get-root
              isnt: http-apache
              frag: "\nServer: Microsoft-IIS")

