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
(import "mosref/prod-http")

(enable-spot-tests)

; Captured from slashdot.org:80
(define apache-response 
"HTTP/1.1 301 Moved Permanently\r\nDate: Thu, 29 Jun 2006 14:05:00 GMT\r\nServer: Apache/1.3.33 (Unix) mod_gzip/1.3.26.1a mod_perl/1.29\r\nLocation: http://slashdot.org/\r\nConnection: close\r\nContent-Type: text/html; charset=iso-8859-1\r\n\r\n<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML><HEAD>\r\n<TITLE>301 Moved Permanently</TITLE>\r\n</HEAD><BODY>\r\n<H1>Moved Permanently</H1>\r\nThe document has moved <A HREF=\"http://slashdot.org/\">here</A>.<P>\r\n<HR>\r\n<ADDRESS>Apache/1.3.33 Server at www.slashdot.org Port 8080</ADDRESS>\r\n</BODY></HTML>\r\n\r\n")

(define stimulus #f)
(s: (set! stimulus (car (find-tcp-stimuli 80))))
(t: (stimulus? _))

(s: (analyze-response '() stimulus apache-response))
(t: (memq 'http-v1 _))
(t: (memq 'http-apache _))
(t: (memq 'http-apache-v1 _))

