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

(module "lib/url")

(define-class url <object>
              (make-url scheme auth path query frag)
              url?

              (scheme url-scheme)
              (auth url-auth)
              (path url-path)
              (query url-query)
              (frag url-frag))

(export <url> make-url url-scheme url-auth url-path url-query url-frag)

(define *url-regex* 
  ;; This beast of a regex is courtesy of the W3C.  
  ;; W3C -- We make simple things hard, and hard things ambiguous.
  (make-regex "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)([?]([^#]*))?(#(.*))?"))

(define (string->url str)
   (define result (match-regex *url-regex* str))
   (unless result (error 'url "string is not a well formed url" str))
   (define result (apply vector result))
   (make-url (vector-ref result 1)
             (vector-ref result 3)
             (vector-ref result 4)
             (vector-ref result 6)
             (vector-ref result 8)))

(define (url->string url)
   (define buf (make-buffer))
   (define scheme (url-scheme url))
   (define auth (url-auth url))
   (define path (url-path url))
   (define query (url-query url))
   (define frag (url-frag url))
   
   (when scheme
     (write-buffer buf scheme)
     (write-buffer buf ":"))

   (when auth
     (write-buffer buf "//")
     (write-buffer buf auth))

   (when path
     (write-buffer buf path))

   (when query
     (write-buffer buf "?")
     (write-buffer buf query))

   (when frag
     (write-buffer buf "#")
     (write-buffer buf frag))
   
   (buffer->string buf))

(export string->url url->string)
