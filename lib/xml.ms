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

;; Taxonomy:
;; <?xml ... ?>
;; <! ... >

(define (make-regex* . rest)
  (make-regex (apply string-append rest)))

(define attr-value "'[^']*'|\"[^\"]\"")
(define identifier "[[:alpha:]_:][[:alnum:]_:.-]*")
(define req-space "[[:space:]]+")
(define opt-space "[[:space:]]*")

(define attr (string-append req-space "(" identifier ")=(" attr-value ")"))
(define attr-list  (string-append "(" attr ")*"))
(define rest   ".*")

; All special XML syntaxes conveniently start with a <, or an &. Since we
; parse entities in a final pass, this means all interesting syntax starts
; with a <..

(define xml-tag     (make-regex* "([^<]*)(<.*)"))

(define (parse-tag str)
  (define m (match-regex xml-tag str))
  (if m
    (cons (car m) 
          (let ((r (cadr m)))
            (or (parse-cdata r)
                (parse-begin r)
                (parse-end r)
                (parse-comment r)
                (error 'xml "nonconformant < found" r))))
    (list str #f #f)))

(define xml-cdata   (make-regex* "^<!\\[CDATA\\[(.*)\\]\\]>(.*)"))

(define (parse-cdata str) (match-regex xml-cdata str))

(define xml-begin   (make-regex* "^<(" 
                                        identifier 
                                        attr-list 
                                        opt-space
                                        "/?"
                                        ")>(.*)"))
(define (parse-begin str)
  (define m (match-regex xml-begin str))
  (if m
    (list (cons 'begin (car m))
          (list-ref m 4))
    #f))

(define xml-end     (make-regex* "^</(" identifier ")>(.*)")) 

(define (parse-end str)
  (define m (match-regex xml-end str))
  (if m
    (cons (cons 'end (car m))
          (cdr m))
    #f))

(define xml-comment (make-regex* "^<!--(.*)-->(.*)"))

(define (parse-comment str)
  (define m (match-regex xml-comment str))
  (if m
    (cons (cons 'comment (car m))
          (cdr m))
    #f))

(define (expat data cdata-fn begin-fn end-fn)
  (until (string=? data "")
    (define r (parse-tag data))
    (define head (car r))
    (define item (cadr r))
    (define tail (cadr (cdr r)))
    (unless (string=? head "") (cdata-fn head))
    (set! data tail)
    (if (string? item)
      (cdata-fn item)
      (case (car item)
        ((begin) (begin-fn (cdr item)))
        ((end) (end-fn (cdr item)))))))

;;; (define xml-header  (make-regex* "^<?xml(.*)?>"))
;;; TODO: Doesn't handle quoted attrs.
;;; (define xml-info    (make-regex* "^<!(.*)>"))
;;; TODO: Doesn't handle quoted attrs.

;; Returns cdata leading up to a tag, the tag, then the unparsed data. 
;; If the tag is false, no tag was found.
;; If the tag is a string, the "tag", here, was character data.

