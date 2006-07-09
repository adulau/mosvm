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
(import "lib/foe")

;;; Wraps func with the necessary logic to start new flows, as a closure that
;;; may be used with lib/http-server and spawn-http-server

(define (spawn-flow portno flow)
  (define sids (dict))

  (spawn-http-server portno
    (function (flow-broker req)
        (define (new-session)
          (define reqs (make-channel))
          
          (print "Sending request; ")
          (print (url->string (http-request-url req)))
          (print " to new session ")
          (print (format reqs))
          (print "\n")

          (send req reqs)
          (flow (make-flow-sid sids reqs) reqs))

      (define sid (http-request-cookie req "sid"))
      (when (not sid) (return (new-session)))

      (define reqs (dict-ref sids sid))
      (when (not reqs) (return (new-session)))
    
      ;(define old-input (http-request-input req))
      ;(define new-input (make-channel))

      ;(set-http-request-input! req new-input)
      ;(send (wait new-input) old-input)
    
      (print "Sending request; ")
      (print (url->string (http-request-url req)))
      (print " to existing session ")
      (print (format reqs))
      (print "\n")

      (send req reqs)
      )))

(define-macro (define-flow formals . body)
  `(define ,formals
     (lambda (^flow-sid^ ^flow-in^)
       ,@body)))

(define (make-flow-sid dict cmd)
  (forever
    (define sid (string-append (format (random-integer 0 *max-imm*))
                               "-"
                               (format (random-integer 0 *max-imm*))
                               "-"
                               (format (random-integer 0 *max-imm*))
                               "-"
                               (format (random-integer 0 *max-imm*))))
    (unless (dict-ref dict sid)
      (dict-set! dict sid cmd)
      (return sid))))

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

(define (flow-ok sid req head body)
  (write-http-response req 
                       200 "OK" 
                       (cons (string-append "Set-cookie: sid=" sid)
                             head)
                       (if (list? body)
                         (sxml->string body)
                         body)))

(define-macro (html-ok html)
  `(flow-ok ^flow-sid^ ^flow-req^ '("Content-type: text/html") ,html))

(define-macro (css-ok html)
  `(flow-ok ^flow-sid^ ^flow-req^ '("Content-type: text/css") ,html))

(define-macro (xml-ok html)
  `(flow-ok ^flow-sid^ ^flow-req^ '("Content-type: text/xml") ,html))

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

  `(begin
     (print "Waiting on ")
     (print (format ^flow-in^))
     (print "\n")
     (let ((^flow-req^ (wait ^flow-in^)))
     (let ,(process-flow-vars flow-vars)
     (print "Got ")
     (print (format ^flow-req^))
     (print "\n")
       ,@flow-body
     (print "Exiting flow.")  
       ))))

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

