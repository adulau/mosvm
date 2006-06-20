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

(module "lib/http-flow")
(import "lib/xml")
(import "lib/iterate")
(import "lib/http-server")

;;; Wraps func with the necessary logic to start new flows, as a closure that
;;; may be used with lib/http-server and spawn-http-server

(define (spawn-flow portno flow)
  (spawn-http-server portno
    (function (flow-broker req)
      (define reqs (make-channel))
      (send req reqs)
      (flow reqs))))

(define-macro (define-flow formals . body)
  `(define ,formals
     (lambda (^flow-in^)
       (define ^flow-sid^ (make-flow-sid))
       ,@body)))

(define (make-flow-sid) ;TODO
  #f)

(define (flow-arg-auth/0 req)
  (url-auth (http-request-url req)))
  
(define (list-tail list count)
  (until (<= count 0)
    (set! list (cdr list))
    (set! count (- count 1)))

  list)

(define (sublist list origin count)
  (define listlen (length list))

  (if (< origin 0 )
    (set! origin (+ listlen origin)))

  (set! list (list-tail list origin))
  (unless list (return #f))
  (unless count (return list))

  (define rest (make-tc))

  (until (<= count 0)
    (if (null? list) (return #f))
    (tc-append! rest (car list))
    (set! list (cdr list))
    (set! count (- count 1)))

  (tc->list rest))

(define (flow-arg-path/0 req)
  (url-path (http-request-url req)))
  
(define (flow-arg-path/1 req index)
  (sublist (http-url-path (http-request-url req))
           index #f))

(define (flow-arg-path/2 req index count)
  (sublist (http-url-path (http-request-url req))
           index count))
  
(define (flow-arg-frag/0 req)
  (url-frag (http-request-url req)))
  
(define (flow-arg-query/0 req)
  (url-query (http-request-url req)))
  
(define (flow-arg-query/1 req key)
  (http-request-arg req key))
  
(define (flow-arg-query/2 req key alt)
  (or (http-request-arg req key) alt))
  
(define (flow-arg-scheme/0 req)
  (url-scheme (http-request-url req)))

(define (flow-arg-cookies/0 req)
  (http-request-cookies req))

(define (flow-arg-cookies/1 req key)
  (http-request-cookies req key))

(define (flow-arg-cookie/2 req key alt)
  (or (http-request-cookies req key) alt))

(define (flow-arg-req/0 req)
  req)

(define (flow-ok req head body)
  (write-http-response req 200 "OK" head (if (list? body)
                                           (sxml->string body)
                                           body)))

(define-macro (html-ok html)
  `(flow-ok ^flow-req^ '("Content-type: text/html") ,html))

(define-macro (css-ok html)
  `(flow-ok ^flow-req^ '("Content-type: text/css") ,html))

(define-macro (xml-ok html)
  `(flow-ok ^flow-req^ '("Content-type: text/xml") ,html))

;;; The Flowlet Macro
;;;
;;; (flowlet ((a query "a")
;;;           (b query "b")
;;;           (path path))
;;;
;;;   (set! a (false-on-error (string->integer a)))
;;;   (set! b (false-on-error (string->integer b)))
;;;
;;;   (html-ok 
;;;     (if (and a b)
;;;       `(html (body (form (* (action . ,path) 
;;;                             (method . post))
;;;                          (input (* (name . "a")
;;;                                    (value . ,(format (or a 0)))))
;;;                          (input (* (type . "submit")
;;;                                    (value . "+")))
;;;                          (input (* (name . "b")
;;;                                    (value . ,(format (or b 0))))))))
;;;       `(html (body (h3 "The answer is " ,(format (+ a b))))))))

(define-macro (flowlet flow-vars . flow-body)
  (define (process-flow-var flow-var)
    (define var-name (car flow-var))
    (define var-type (cadr flow-var))
    (define var-args (cdr (cdr flow-var)))

    `(,var-name (,(make-symbol 'flow-arg- 
                               var-type 
                               '/ 
                               (string->symbol (format (length var-args))))
                  ^flow-req^
                  ,@var-args)))

  (define (process-flow-vars flow-vars)
    (map process-flow-var flow-vars))

  `(let ((^flow-req^ (wait ^flow-in^)))
     (let ,(process-flow-vars flow-vars)
       ,@flow-body)))

(define-macro (false-on-error . body)
  `(guard (lambda x #f)
          ,@body))

(export define-flow spawn-flow make-flow-sid
        flow-arg-auth/0
        flow-arg-cookies/0 flow-arg-cookies/1 flow-arg-cookies/2
        flow-arg-frag/0 
        flow-arg-path/0 flow-arg-path/1 flow-arg-path/2
        flow-arg-query/0 flow-arg-query/1 flow-arg-query/2
        flow-arg-req/0
        flow-arg-scheme/0  
        flow-ok
        ;flow-arg-url/0
        html-ok css-ok xml-ok
        flowlet
        false-on-error
        )

