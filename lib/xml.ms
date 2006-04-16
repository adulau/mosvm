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
                (parse-decl r)
                (parse-ver r)
                (error 'xml "nonconformant < found" r))))
    (list str #f #f)))

(define xml-cdata   (make-regex* "^<!\\[CDATA\\[(.*)\\]\\]>(.*)"))

(define (parse-cdata str) (match-regex xml-cdata str))

(define xml-begin   (make-regex* "^<(" 
                                 identifier 
                                 ")("
                                 attr-list 
                                 ")"
                                 opt-space
                                 "(/)?"
                                 ">(.*)"))
(define (parse-begin str)
  (define m (match-regex xml-begin str))
  (if m
    (list (cons (if (list-ref m 5) 'tag 'begin)
                (cons (car m)
                      (parse-attrs (or (cadr m) ""))))
          (list-ref m 6))
    #f))

(define xml-end     (make-regex* "^</(" identifier ")>(.*)")) 

(define (parse-end str)
  (define m (match-regex xml-end str))
  (if m
    (cons (list 'end (car m))
          (cdr m))
    #f))

(define xml-comment (make-regex* "^<!--(.*)-->(.*)"))

(define (parse-comment str)
  (define m (match-regex xml-comment str))
  (if m
    (cons (cons 'comment (car m))
          (cdr m))
    #f))

(define xml-ver (make-regex* "<\\?xml(" attr-list ")" "\\?>(.*)"))

(define xml-attr (make-regex* opt-space "(" identifier ")"
                              opt-space "=" opt-space
                              "(" attr-value ")"))

(define (parse-attrs str)
  (map (lambda (p)
         (define key (car p))
         (define val (cadr p))
         (cons key (substring val 1 (- (string-length val) 2))))
       (or (match-regex* xml-attr str) '())))

(define (parse-ver str)
  (define m (match-regex xml-ver str))
  (if m
    (list (cons 'ver (parse-attrs (car m)))
          (list-ref m 4))
    #f))

(define (expat event-fn data)
;;; Anatomy of a BEGIN event: <a href='123'>
;;; '(begin tag-name . tag-attrs)
;;; Anatomy of a TAG event: <br />
;;; '(begin tag-name . tag-attrs)
;;; Anatomy of a END event: </a>
;;; '(end tag-name)
;;; Anatomy of a VER event: <?xml version="1.0"?>
;;; '(ver . ver-attrs)
;;; Anatomy of a DECL event: <!DOCTYPE who-really-cares>
;;; '(decl . decl-frags)

  (until (string=? data "")
    (define r (parse-tag data))
    (define head (car r))
    (define item (cadr r))
    (define tail (cadr (cdr r)))
    (unless (string=? head "") (event-fn (list 'cdata head)))
    (set! data tail)
    (if (string? item)
      (when (> (string-length item) 0)
        (event-fn (list 'cdata item)))
      (event-fn item))))

(define xml-decl (make-regex* "^<!" identifier "(" req-space identifier ")*>"))

(define (parse-decl str)
  (define m (match-regex xml-decl str))
  (if m
    (list (list 'decl (car m))
          (list-ref m 4))
    #f))

;;; (define xml-info    (make-regex* "^<!(.*)>"))
;;; TODO: Doesn't handle quoted attrs.

;; Returns cdata leading up to a tag, the tag, then the unparsed data. 
;; If the tag is false, no tag was found.
;; If the tag is a string, the "tag", here, was character data.

