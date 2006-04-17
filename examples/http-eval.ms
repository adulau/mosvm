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
(import "lib/format")
(import "lib/eval")

(define page-header
  (string-append "<html><head>"
                 "<title>MOSVM HTTP / REPL</title>"
                 "</head><body>"))

(define page-footer
  (string-append "</body></html>"))

(define read-expr-form
  (string-append "<form action='/' method='post'"
                 "<textarea name='q' rows='37' cols='72'></textarea>"
                 "<br />"
                 "<input type='submit' name='action' value='Eval' />"
                 "</form>"))

(define read-expr-page
  (string-append page-header read-expr-form page-footer))

(define (respond-with-page req page)
  (write-http-response req 200 "OK"
                       '("Content-Type: text/html") 
                       page))

(define-macro (save-error err . stmts)
    `(guard (lambda (%x) (set! ,err %x)) ,@stmts))

(define (http-eval-session req)
  (define method (http-request-method req))
  
  (unless (or (string=? method "GET")
              (string=? method "POST"))

    (error 'http "Method not supported" 400))
  
  (define url (http-request-url req))
  (define expr-src (http-request-arg req "q"))
  (define expr #f)
  (define err #f)
  (define result #f)
  (define evald #f)

  (define (expr-error-page)
    (string-append page-header
                   "<h1> PARSE:" (xml-escape (car (error-info err))) "</h1>"
                   (xml-escape expr-src) "<br />"
                   read-expr-form
                   page-footer))

  (define (eval-error-page)
    (string-append page-header
                   "<h1> EVAL:" (xml-escape (car (error-info err))) "</h1>"
                   (xml-escape expr-src) "<br />"
                   read-expr-form
                   page-footer))

  (define (eval-expr-page)
    (string-append page-header
                   (xml-escape (value->string result))  "<br />"
                   read-expr-form 
                   page-footer))

  (when expr-src 
    (save-error err (set! expr (string->exprs expr-src)))
    (when expr
      (save-error err (set! result (exec expr))
                      (set! evald #t))))
  
  (respond-with-page req (cond
                           ((not expr-src) read-expr-page)
                           ((not expr)     (expr-error-page))
                           ((not evald)    (eval-error-page))
                           (else           (eval-expr-page)))))

(define (exec expr)
  ((assemble (optimize (compile expr)))))

(define (http-eval portno)
  (spawn-http-server portno http-eval-session))

