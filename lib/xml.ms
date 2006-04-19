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

(module "lib/xml")
(import "lib/iterate")
(import "lib/port")
(import "lib/trace")

(define (make-regex* . rest)
  (make-regex (apply string-append rest)))

(define attr-value "'[^']*'|\"[^\"]*\"")
(define identifier "[[:alpha:]_:][[:alnum:]_:.-]*")
(define req-space "[[:space:]]+")
(define opt-space "[[:space:]]*")

(define all-space (make-regex "^[[:space:]]*$"))

(define decl-value (string-append "(" identifier "|" attr-value ")" ))

(define attr (string-append req-space 
                            "(" identifier ")" 
                            opt-space "=" opt-space 
                            "(" attr-value ")"))

(define attr-list  (string-append "(" attr ")*"))
(define rest   ".*")

; All special XML syntaxes conveniently start with a <, or an &. Since we
; parse entities in a final pass, this means all interesting syntax starts
; with a <..

(define xml-tag     (make-regex* "([^<]*)(<.*)"))

(define (parse-tag str)
  (define m (match-regex xml-tag str))
  (guard (lambda (err)
           (unless (eq? (error-key err) 'xml-inc)
             (re-error err))
           (define info (error-info err))
           (error 'xml-inc (car info) (string-append (car m)
                                                     (cadr info))))
     (if m
       (cons (car m) 
             (let ((r (cadr m)))
               (or (parse-cdata r)
                   (parse-begin r)
                   (parse-end r)
                   (parse-comment r)
                   (parse-decl r)
                   (parse-ver r)
                   (error 'xml-inc "< unmatched or garbage" r))))
       (list str #f ""))))

(define (parse-cdata str) 
  (if (string-begins-with? str "<![CDATA[")
    (begin 
      (define cdata-len (string-find str "]]>"))
      (if cdata-len
        (set! cdata-len (- cdata-len 9))
        (error 'xml-inc "CDATA section incomplete" str))
      (list (substring str 9 cdata-len)
            (substring str (+ 12 cdata-len) 
                       (- (string-length str) 12 cdata-len))))
    #f))

(define xml-begin   (make-regex* "^<(" 
                                 identifier 
                                 ")("
                                 attr-list 
                                 ")"
                                 opt-space
                                 "(/)?"
                                 opt-space
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

(define xml-ver (make-regex* "<\\?xml(" attr-list ")" opt-space "\\?>(.*)"))

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
    (unless (string=? head "") 
      (event-fn (list 'cdata head)))
    (set! data tail)
    (cond
      ((string? item) (when (> (string-length item) 0)
                        (event-fn (list 'cdata item))))
      ((pair? item) (set! report (event-fn item))))))


(define xml-decl (make-regex* "^<!" identifier 
                              "((" req-space decl-value ")*)"
                              opt-space ">(.*)"))

(define (parse-decl str)
  (define m (match-regex xml-decl str))
  (if m
    (list (list 'decl (car m))
          (list-ref m 3))
    #f))

(define-class xml-context <object>
              (make-xml-context loc tag attrs inv)
              xml-context?
              (tag xml-context-tag)
              (attrs xml-context-attrs)
              (inv xml-context-inv)
              (loc xml-context-loc))

(define (make-sxml-parser)
  (define context (make-xml-context #f "*TOP*" '() (make-tc)))

  (define (new-context tag attrs)
    (make-xml-context context tag attrs (make-tc)))

  (define (new-sxml tag inv attrs)
    (define sxml inv)
    (unless (null? attrs)
      (set! inv (cons (cons '@ (map (lambda (attr)
                                      (cons (string->symbol (car attr))
                                            (cdr attr)))
                                      attrs) )
                      inv)))
    (cons (string->symbol tag) inv))

  (define (context->sxml)
    (define sxml (new-sxml (xml-context-tag context)
                           (tc->list (xml-context-inv context))
                           (xml-context-attrs context)))
    (set! context (xml-context-loc context))
    sxml)

  (define (add-sxml sxml)
    (tc-append! (xml-context-inv context) sxml))

  (define (add-text text)
    (unless (match-regex all-space text)
        (tc-append! (xml-context-inv context) text)))

  (define (on-tag-event tag attrs)
    (add-sxml (new-sxml tag '() attrs)))

  (define (on-cdata-event text)
    (add-text text))

  (define (on-begin-event tag attrs)
    (set! context (new-context tag attrs)))

  (define (on-end-event tag)
    (unless (string=? tag (xml-context-tag context))
      (error 'xml-conform "Unmatched close tag." tag (xml-context-tag context)))
    (add-sxml (context->sxml)))
  
  (define (on-cdata-event data)
    (add-text data))

  (lambda (event)
    (if (eq? event 'done)
      (begin
        ;;TODO: Assert context is #f.
        (define sxml #f)
        (until (not context)
          (set! sxml (context->sxml))
          (when context (add-sxml sxml)))
        sxml)
      (begin
        (define event-key (car event))
        (define event-data (cdr event))
        (case event-key 
          ((begin) (on-begin-event (car event-data) (cdr event-data)))
          ((end)   (on-end-event   (car event-data)))
          ((cdata) (on-cdata-event (car event-data)))
          ((tag)   (on-tag-event   (car event-data) (cdr event-data))))))))

(define (expat-port func port)
  (define data "")
  (until (closed? port)
    (define more (read 256 port))
    (unless (eof-object? more)
      (set! data (string-append data more))
      (guard (lambda (err)
               (unless (eq? (error-key err) 'xml-inc)
                 (re-error err))
               (set! data (cadr (error-info err))))
               
           (expat func data)
           (set! data "")))))

(define (make-sxml (<string> src))
  (define parser (make-sxml-parser))
  (expat parser src)
  (parser 'done))

(define (make-sxml (<port> src))
  (define parser (make-sxml-parser))
  (expat-port parser src)
  (parser 'done))

(define (get-sxml-items sxml)
  (if (pair? sxml)
    (begin
      (define len (length sxml))
      (if (< len 2)
        '()
        (begin
          (define tag (cadr sxml))
          (if (and (pair? tag) (eq? (car tag) '@))
            (cdr (cdr sxml))
            (cdr sxml)))))
    '()))

(define (get-sxml-attrs sxml)
  (if (pair? sxml)
    (begin
      (define len (length sxml))
      (if (< len 2)
        '()
        (begin
          (define tag (cadr sxml))
          (if (and (pair? tag) (eq? (car tag) '@))
            (cdr tag)
            '()))))
    '()))

(define (get-sxml-attr sxml key)
  (define attr (assq key (get-sxml-attrs sxml)))
  (if attr (cdr attr) #f))

(define (get-sxml-item sxml index)
  (if (integer? index)
    (list-ref (get-sxml-items sxml) index)
    (assq index (get-sxml-items sxml))))

(define (get-sxml-item* sxml index)
  (if (integer? index)
    (list-ref (get-sxml-items sxml) index)
    (filter (lambda (item) (eq? (car item) index)) (get-sxml-items sxml))))

(export make-sxml get-sxml-items get-sxml-attrs
        get-sxml-attr get-sxml-item get-sxml-item*)

;;; (define (sxml->string sxml) ...)
;;; (define (write-sxml sxml port) ...)

