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
(import "lib/tcp-server")

(define-class http-request <object>
              (make-http-request method headers url version body input output)
              http-request?
              (method http-request-method)
              (headers http-request-headers)
              (url http-request-url)
              (version http-request-version)
              (body http-request-body)
              (input http-request-input set-http-request-input!)
              (output http-request-output))

(define (http-request-arg http-request key)
  (define args (http-url-args (http-request-url http-request)))
  (if args (dict-ref args key) #f))

(define (http-request-header http-request key)
  (dict-ref (http-request-headers http-request) key))

(export <http-request> http-request? http-request-method http-request-headers
        http-request-url http-request-version http-request-body 
        http-request-input http-request-output http-request-header 
        http-request-arg)

(define *http-word* (make-regex "[^[:space:]]+"))
(define *http-header* (make-regex "^([^:]+):[[:space:]]+(.*)$"))

(define (read-http-request input)
  (define buffer (make-string))
  (define last-line #f)
  (define (next-line)
    (forever
      (set! last-line (string-read-line! buffer))
      (when last-line (return last-line))

      (define evt (wait input))
      (cond
        ((string? evt)
         (string-append! buffer evt))
        (else 
          (set! last-line evt)
          (return evt)))))

  (define (next-block size)
    (until (>= (string-length buffer) size)
      (define evt (wait input)
        (cond
          ((string? evt)
           (string-append! buffer evt))
          (else
            (return evt)))))
    (string-read! buffer size))

  (when (not (string? (next-line)))
    (error 'http "expected request line" 400 last-line))

  (define match (match-regex* *http-word* last-line))

  (unless (and match (= (length match) 3))
    (error 'http "request line malformed" 400 last-line))

  (define method (car match))
  (define url (cadr match))
  (define version (cadr (cdr match)))
  (define headers (dict))

  (define (read-headers)
    (forever 
      (cond 
        ((not (string? (next-line)))
         (error 'http "expected header line or null line" 400 last-line))
        ((empty-string? last-line)
         (return headers))
        (else
          (define match (match-regex *http-header* last-line))
          (unless match
            (error 'http "header line malformed" 400 last-line))
          (dict-set! headers (car match) (cadr match))))))

  (read-headers)

  (when (dict-set? headers "Transfer-Encoding")
    ;; Piss off. We're a simple little server, not an operating system..
    (error 'http "transfer encodings unimplemented" 501))

  (define body #f)
  (define content-length (dict-ref headers "Content-Length"))
  (define content-type #f)

  (when content-length
    (guard (lambda (x) 
             ;; Integer or die!
             (error 'http "content length malformed" 400 last-line))
           (set! content-length (string->integer content-length)))
    (set! body (next-block content-length))
    (unless (string? body)
      (error 'http "content body malformed" 400 body))
    (set! content-type (dict-ref headers "Content-Type"))
    (when (equal? content-type "application/x-www-form-urlencoded")
      (set! url (string-append url "?" body))))

  (define url (string->url url "http"))

  ;TODO: Do we want to channel-prepend any excess in the buffer?

  (make-http-request method headers url version body #f input))  

(define *crlf* "\r\n")

(define (write-http-response port code reason headers body)
  (if (http-request? port)
    (set! port (http-request-input port)))
  (define buf (make-string))
  (string-append! buf "HTTP/1.1 ")
  (string-append! buf (number->string code))
  (string-append! buf " ")
  (string-append! buf reason)
  (string-append! buf *crlf*)
  (for-each (lambda (header) (string-append! buf header)
                             (string-append! buf *crlf*))
            headers)
  (string-append! buf *crlf*)
  (string-append! buf body)
  (send buf port))

(define (spawn-http-server portno http-responder)
  (define (serve-http-session)
    (define in (input))
    (define out (output))
    (guard (lambda (e)
             (unless (eq? (error-key e) 'http) 
               (re-error e))
             (define info (error-info e))
             (write-http-response out (cadr info) (car info)
                                  '("Content-Type: text/plain")
                                  (car info))))
       (define req (read-http-request in))
       (set-http-request-input! req out)
       (http-responder req)
       (send 'close))

  (spawn-tcp-server portno serve-http-session))

(export read-http-request write-http-response spawn-http-server)
;;; MOSVM2
