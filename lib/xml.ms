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

;TODO: Exporting all for test purposes.
;
(module "lib/xml")
(export make-sxml get-sxml-items get-sxml-attrs string->sxml
       get-sxml-attr get-sxml-item get-sxml-item* 
       get-sxml-tag has-sxml-tag? has-sxml-attr? sxml-drill)

(import "lib/iterate")
(import "lib/trace")

; All special XML syntaxes conveniently start with a <, or an &. Since we
; parse entities in a final pass, this means all interesting syntax starts
; with a <..

(define (parse-data data)
  (define tag-ix (string-find data "<" ))
  (if tag-ix 
    (guard (lambda (err)
             (unless (eq? (error-key err) 'xml-inc)
               (re-error err))
             (define info (error-info err))
             (error 'xml-inc (car info) data))
           (parse-tag (string-head data tag-ix)
                      (string-tail data tag-ix)))
    (list data #f "")))

(define (parse-tag pre tag)
    (cons pre
          (or (parse-cdata tag)
              (parse-comment tag)
              (parse-decl tag)
              (parse-pi tag)
              (parse-end tag)
              (parse-begin tag)
              (error 'xml-inc "< unmatched or garbage"))))

(define (parse-cdata str) 
  (step "CDATA" str)
  (if (string-begins-with? str "<![CDATA[")
    (begin 
      (define cdata-len (string-find str "]]>"))
      (if cdata-len
        (set! cdata-len (- cdata-len 9))
        (error 'xml-inc "CDATA section incomplete"))
      (list (substring str 9 cdata-len)
            (substring str (+ 12 cdata-len) 
                       (- (string-length str) 12 cdata-len))))
    #f))

(define (parse-comment str)
  (step "COMMENT" str)
  (if (string-begins-with? str "<!--")
    (begin
      (define end (string-find str "-->"))
      (unless end
        (error 'xml-inc "Comment incomplete"))
      (list (list 'comment (substring str 4 (- end 4)))
            (substring str (+ end 3) 
                       (- (string-length str) 3 end))))
    #f))

(define-macro (step . rest) '(begin))
;(define (step phase str) (print phase) (dump-string str))
  
(define (parse-question scan)
  (define ch (scanner-next scan))
  (unless (= ch *qm-char*)
    (error 'xml "expected '?' to complete tag" ch)))

(define (parse-completion scan)
  (define ch (scanner-next scan))
  (unless (= ch *gt-char*)
    (error 'xml "expected '>' to complete tag" ch)))

(define (parse-decl str)
  ; This does not correctly handle nested attributes.  Thank you, W3C, for
  ; introducing seventeen different syntaxes in your simple document format.
  (step "DECL" str)
  ;;; Any error we encounter may be because of an incomplete read. We 
  ;;; make all xml errors xml-inc errors.
  (guard (lambda (e) 
           (if (eq? 'xml (error-key e))
             (apply error 'xml-inc (error-info e))
             (re-error e)))
     (if (string-begins-with? str "<!")
       (begin
         ;(define scan (copy-string (string-tail str 2)))
         (define scan str)
         (string-read! str 2)

         (define tag  (parse-ident scan))
         (scanner-strip scan)
         (define atoms (parse-atoms scan))
         (scanner-strip scan)
         (parse-completion scan)
         (list (cons 'decl (cons tag atoms))
               (scanner->string scan)))
       #f)))

(define (parse-pi str)
  (step "PI" str)

  (if (string-begins-with? str "<?")
    (begin
      ;(define scan (copy-string (string-tail str 2)))
      (define scan str)
      (string-read! str 2)

      (define tag  (parse-ident scan))
      (scanner-strip scan)
      (define attrs (parse-attrs scan))
      (scanner-strip scan)
      (parse-question scan)
      (parse-completion scan)
      (list (cons 'pi (cons tag attrs))
            (scanner->string scan)))
    #f))

(define (parse-end str)
  (step "END" str)

  (if (string-begins-with? str "</")
    (begin
      ;(define scan (copy-string (string-tail str 2)))
      (define scan str)
      (string-read! str 2)

      (define tag  (parse-ident scan))
      (scanner-strip scan)
      (parse-completion scan)
      (list (list 'end tag)
            (scanner->string scan)))
    #f))
; TODO: We should not be copying -- we should attempt a parse-indent, and backfeed.
(define (parse-begin str)
  (step "BEGIN" str)
  
  ;(define scan (copy-string str))
  ;(scanner-next scan) ;; Drop that <..
  
  (define scan str)
  (string-read! str 1)

  (define tag  (parse-ident scan))

  (scanner-strip scan)
  (define attrs (parse-attrs scan))
  
  (scanner-strip scan)
  (define stroke (parse-stroke scan))

  (parse-completion scan)

  (list (cons (if stroke 'tag 'begin)
              (cons tag attrs))
        (scanner->string scan)))

(define (parse-stroke scan)
  (define ch (scanner-next scan))
  (if (= ch *stroke-char*)
    #t
    (begin
      (scanner-drop scan ch)
      #f)))
    
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
    (define r (parse-data data))
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


(define-class xml-context <object>
              (make-xml-context loc tag attrs inv buf)
              xml-context?
              (tag xml-context-tag)
              (attrs xml-context-attrs)
              (inv xml-context-inv)
              (loc xml-context-loc)
              (buf xml-context-buf set-xml-context-buf!))

(define (make-sxml-parser)
  (define context (make-xml-context #f '*TOP* '() (make-tc) (make-string)))

  (define (new-context tag attrs)
    (make-xml-context context tag attrs (make-tc) (make-string)))

  (define (new-sxml tag inv attrs)
    (unless (null? attrs)
      (set! inv (cons (cons '* attrs)
                      inv)))
    (cons tag inv))

  (define (context->sxml)
    (define sxml (new-sxml (xml-context-tag context)
                           (tc->list (xml-context-inv context))
                           (xml-context-attrs context)))
    (set! context (xml-context-loc context))
    sxml)

  (define (add-sxml sxml)
    (tc-append! (xml-context-inv context) sxml))

  (define (add-text text)
    (define buf (xml-context-buf context))
    (unless buf
      (set! buf (make-string))
      (set-xml-context-buf! context buf))
    (string-append! buf text))

  (define (flush-buf)
    (define buf (xml-context-buf context))
    (when buf
      (define text (strip buf))
      (unless (string=? text "")
        (add-sxml buf))
      (set-xml-context-buf! context #f)))

  (define (on-tag-event tag attrs)
    (flush-buf)
    (add-sxml (new-sxml tag '() attrs)))

  (define (on-cdata-event text)
    (add-text text))

  (define (on-begin-event tag attrs)
    (flush-buf)
    (set! context (new-context tag attrs)))

  (define (on-end-event tag)
    (flush-buf)
    (unless (eq? tag (xml-context-tag context))
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

(define (string->sxml src)
  (define parser (make-sxml-parser))
  (expat parser src)
  (parser 'done))

(define (make-sxml (<string> src))
  (string->sxml src))

(define (make-sxml (<channel> src))
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
          (if (and (pair? tag) (eq? (car tag) '*))
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
          (if (and (pair? tag) (eq? (car tag) '*))
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

(define (get-sxml-tag sxml)
  (if (pair? sxml)
    (car sxml)
    #f))

(define (has-sxml-tag? sxml tag)
  (eq? (get-sxml-tag sxml) tag))

(define (has-sxml-attr? sxml key value)
  (define x (get-sxml-attr sxml key))
  (eqv? x value))

(define (sxml-drill sxml . tests)
  (define test #f)
  (define items (get-sxml-items sxml))

  (until (or (null? items)
             (null? tests))

    (set! test (car tests))
    (set! tests (cdr tests))
    (set! items (filter test items))

    (unless (null? tests)
      (define tc (make-tc))
      (for-each (lambda (item)
                  (tc-splice! tc (get-sxml-items item)))
                items)
      (set! items (tc->list tc))))

  items)

;;; (define (sxml->string sxml) ...)
;;; (define (write-sxml sxml port) ...)

(define *qm-char* 63)
(define *ident-chars* (dict))
(define *lt-char* 60)
(define *gt-char* 62)
(define *apos-char* 39)
(define *quot-char* 34)
(define *stroke-char* 47)
(define *equal-char* 61)

(define (add-ident-char st) (dict-set! *ident-chars* (string-ref st 0) #t))
(define (add-ident-range a b)
  (set! a (string-ref a 0))
  (set! b (string-ref b 0))
  (while (<= a b)
    (dict-set! *ident-chars* a #t)
    (set! a (+ a 1))))

(add-ident-char "-")
(add-ident-char "_")
(add-ident-range "a" "z")
(add-ident-range "A" "Z")
(add-ident-range "0" "9")

(define (parse-ident scan)
  (define ident (make-string))
  (define done #f)

  (until done
    (define ch (scanner-next scan))
    (if (dict-ref *ident-chars* ch)
      (string-append-byte! ident ch)
      (begin 
        (set! done #t)
        (scanner-drop scan ch))))

  (if (empty-string? ident)
    #f
    (string->symbol ident)))

(define (parse-idents scan)
  (define idents (make-tc))
  (define done #f)
  (until done
    (scanner-strip scan)
    (define ident (parse-ident scan))
    (if ident
      (tc-append! idents ident)
      (set! done #t)))
  (tc->list idents))

(define (parse-value scan)
  (define quot (scanner-next scan))

  (if (or (= quot *apos-char*)
          (= quot *quot-char*))
    (begin
      (define done #f)
      (define value (make-string))
      (until done
         (define ch (scanner-next scan))
         (if (= ch quot)
           (set! done #t)
           (string-append-byte! value ch)))
      value)
    (begin
      (scanner-drop scan quot)
      #f)))

(define (parse-values scan)
  (define values (make-tc))
  (define done #f)
  (until done
    (scanner-strip scan)
    (define value (parse-value scan))
    (if value
      (tc-append! values value)
      (set! done #t)))
  (tc->list values))

(define (parse-attr scan)
  (step "ATTR" scan)
  (define key (parse-ident scan))
  (if key 
    (begin
      (scanner-strip scan)

      (define ch (scanner-next scan))
      (unless (= *equal-char* ch)
        (error 'xml "expected = in attribute, got" ch))

      (scanner-strip scan)
      (define value (parse-value scan))
      (unless value 
        (error 'xml "expected quoted value after = in attribute"))
      (cons key value))
    #f))

(define (parse-attrs scan)
  (step "BEG-ATTRS" scan)
  (define attrs (make-tc))
  (define done #f)

  (until done
    (scanner-strip scan)
    (step "ATTRS-STRIP" scan)
    (define attr (parse-attr scan))
    (if attr
      (tc-append! attrs attr)
      (set! done #t)))

  (step "END-ATTRS" scan)
  (tc->list attrs))

(define (parse-atom scan)
  ; Would it have killed <!...> to use one or the other?
  (or (parse-value scan)
      (parse-ident scan)))

(define (parse-atoms scan)
  (define atoms (make-tc))
  (define done #f)

  (until done
    (scanner-strip scan)
    (define atom (parse-atom scan))
    (if atom
      (tc-append! atoms atom)
      (set! done #t)))

  (tc->list atoms))

(define (scanner-next scanner)
  (if (empty-string? scanner)
    (error 'xml-inc "xml tag incomplete")
    (string-read-byte! scanner)))

(define (scanner-strip scanner)
  (string-skip-space! scanner))

(define (scanner->string scanner)
  scanner)

(define (scanner-drop scanner ch)
  (string-prepend! scanner ch))

;;; MOSVM2
