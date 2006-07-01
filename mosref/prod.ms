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

(module "mosref/prod")
(import "lib/record")
(import "lib/args-fu")

; "mosref/prod" does AMAP-like functionality for MOSREF, with many notable 
; exceptions -- mosref/prod employs rudimentary expert system techniques to 
; greatly reduce CPU demands, and eliminate false positives.  ( For example, 
; an IIS rule isn't checked if the server has already been identified as an 
; Apache server. )

; The tcp-stimulus macro registers a stimulus, which, when given a TCP stream, 
; may elicit a response that may be analyzed by MOSREF to classify a service 
; discovered by mosref/scanner.
;
; (tcp-stimulus id-symbol
;               [ports: port0 portN ...]
;               "stimulus-string")
; 
; The ports field specifies a list of ports that are good candidates for this 
; stimulus.

;(tcp-stimulus http-get-root 
;              ports: 80 81 82 8000 8081 8888
;              "GET / HTTP/1.0\r\n\r\n")

(define *tcp-stimuli-by-port* (dict))
(define *tcp-stimuli-by-id* (dict))

(define-record-type stimulus 
                    (make-stimulus id proto ports func responses)
                    stimulus?
                    (id stimulus-id)
                    (proto stimulus-proto)
                    (ports stimulus-ports)
                    (func stimulus-func)
                    (responses stimulus-responses))

(export stimulus-id stimulus-proto stimulus-ports stimulus-func 
        stimulus-responses stimulus?
        tcp-stimulus find-tcp-stimuli register-stimulus 
        *tcp-stimuli-by-id* *tcp-stimuli-by-port*)

(define (register-stimulus id-table port-table proto id ports func)
  (define rule (make-stimulus id proto ports func (make-tc)))
  (dict-set! id-table id rule)
  (define (register-stimulus/port port)
    (define row (dict-ref port-table port))
    (unless row
      (set! row (make-tc))
      (dict-set! port-table port row))
    (tc-append! row rule))
  (for-each register-stimulus/port ports))

(define (find-stimuli table port)
  (define row (dict-ref table port))
  (if row (tc->list row) '()))

(define (find-tcp-stimuli port)
  (find-stimuli *tcp-stimuli-by-port* port))

(define-macro (tcp-stimulus . args)
  (define (parse-tcp-stimulus id ports stim)
    `(register-stimulus *tcp-stimuli-by-id* *tcp-stimuli-by-port* 
                        'tcp ',id ',ports
                        (function (,(make-symbol 'stim- id) stream)
                                  (send ,stim stream))))

  (apply parse-tcp-stimulus (parse-fu 1 '(ports:) 1 args)))

; A response is a criteria that is checked against a service's response to a particular
; stimulus.  
;
; To conserve CPU resources, a response may be restricted to a dependency on
; another response -- if the response was not satisfied, the response will not be
; satisfied.  Required responses must be defined before the current response.
;
; All responses associated with a given stimulus are tested in sequence
; (tcp-response id-symbol
;               to: stimulus-id-symbol
;               [is: response-id-symbol ...]
;               [isnt: response-id-symbol ...] 
;               head: | frag: string)

; Probably don't need proto and id..
(define (register-response stimulus proto id func)
  (tc-append! (stimulus-responses stimulus) func))

(define-macro (tcp-response . args)
  (define (parse-tcp-response id to is isnt type frag) 
    (define (compile-is is)
      `(unless (memq ',is tags) 
         ;(print "Failed Is: ")
         ;(print (format ',is))
         ;(print " for: ")
         ;(print (format ',id))
         ;(print *line-sep*)
         (return tags)))

    (define (compile-isnt isnt)
      `(when (memq ',isnt tags) 
         ;(print "Failed Isnt: ")
         ;(print (format ',isnt))
         ;(print " for: ")
         ;(print (format ',id))
         ;(print *line-sep*)
         (return tags)))

    (define (compile-head head)
      `(unless (string-begins-with? response ',head)
         ;(print "Failed Head: ")
         ;(print (format ',head))
         ;(print " for: ")
         ;(print (format ',id))
         ;(print *line-sep*)
         (return tags)))

    (define (compile-frag frag)
      `(unless (string-find response ',frag)
         ;(print "Failed Frag: ")
         ;(print (format ',frag))
         ;(print " for: ")
         ;(print (format ',id))
         ;(print *line-sep*)
         (return tags)))

    (unless (= (length to) 1)
      (error 'prod "expected one argument to to:" to))

    (unless (member type '(head: frag:))
      (error 'prod "expected either head: or frag:" type))

    (unless (string? frag)
      (error 'prod "expected string" frag))
   
    `(register-response (dict-ref *tcp-stimuli-by-id* ',(car to))
                        'tcp
                        ',id
                        (function (,(make-symbol 'resp- id) response tags)
                                  ,@(map compile-is is)
                                  ,@(map compile-isnt isnt)
                                  ,(case type
                                     ((head:) (compile-head frag))
                                     ((frag:) (compile-frag frag)))
                                  (cons ',id tags))))
 
    (apply parse-tcp-response (parse-fu 1 '(to: is: isnt:) 2 args)))

(define (analyze-response stimulus response)
  (define tags '())
  (define (run-response-rule rule) 
    (set! tags (rule response tags)))

  (for-each run-response-rule (tc->list (stimulus-responses stimulus)))
  tags)

(export tcp-response register-response analyze-response)

