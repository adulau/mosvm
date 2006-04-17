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

; TODO: Parse http-request-body into URL args.

(module "lib/http-server")
(import "lib/http-url")
(import "lib/conn")

(define-class http-request <object>
              (make-http-request method headers url version body port)
              http-request?
              (method http-request-method)
              (headers http-request-headers)
              (url http-request-url)
              (version http-request-version)
              (body http-request-body)
              (port http-request-port))

(define (http-request-arg http-request key)
  (define args (http-url-args (http-request-url http-request)))
  (if args (dict-ref args key) #f))

(define (http-request-header http-request key)
  (dict-ref (http-request-headers http-request) key))

(export <http-request> http-request? http-request-method http-request-headers
        http-request-url http-request-version http-request-body 
        http-request-port http-request-header http-request-arg)

(define *http-word* (make-regex "[^[:space:]]+"))
(define *http-header* (make-regex "^([^:]+):[[:space:]]+(.*)$"))

(define (read-http-request port)
  (define line (read-line port))
  (if (eof-object? line) 
    line
    (begin
      (define match (match-regex* *http-word* line))

      (unless (and match (= (length match) 3))
        (error 'http "request line malformed" 400 line))

      (define method (car match))
      (define url (cadr match))
      (define version (cadr (cdr match)))
      (define headers (dict))
      (define done #f)

      (until done 
        (set! line (read-line port))
        (if (string=? line "")
          (set! done #t)
          (begin
            (set! match (match-regex *http-header* line))
            (unless match
              (error 'http "header line malformed" 400 line))
            (dict-set! headers (car match) (cadr match)))))
    
      (when (dict-set? headers "Transfer-Encoding")
        ;; Piss off. We're a simple little server, not an operating system..
        (error 'http "transfer encodings unimplemented" 501))
      
      (define body #f)
      (define content-length (dict-ref headers "Content-Length"))
      (when content-length
        (guard (lambda (x) 
                 ;; Integer or die!
                 (error 'http "content length malformed" 400 line))
               (set! content-length (string->integer content-length)))
        (set! body (read content-length port)))

      (define url (string->url url "http"))

      (make-http-request method headers url version body port))))  

(define *crlf* "\r\n")

(define (write-http-response port code reason headers body)
  (if (http-request? port)
    (set! port (http-request-port port)))
  (define buf (make-buffer))
  (write-buffer buf "HTTP/1.1 ")
  (write-buffer buf (number->string code))
  (write-buffer buf " ")
  (write-buffer buf reason)
  (write-buffer buf *crlf*)
  (for-each (lambda (header) (write-buffer buf header)
                             (write-buffer buf *crlf*))
            headers)
  (write-buffer buf *crlf*)
  (write-buffer buf body)
  (write (buffer->string buf) port))

(define (spawn-http-server portno http-responder)
  (define (serve-http-session)
    (define port (current-input-port))
    (guard (lambda (e)
             (unless (eq? (error-key e) 'http) 
               (re-error e))
             (define info (error-info e))
             (unless (closed? port)
               (write-http-response port (cadr info) (car info)
                                    '("Content-Type: text/plain")
                                    (car info))))
       (define req (read-http-request port))
       (http-responder req)
       (close port)))

  (spawn-tcp-server portno serve-http-session))

(export read-http-request write-http-response spawn-http-server)
