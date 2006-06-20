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
(export get-sxml-items get-sxml-attrs string->sxml sxml->string
       get-sxml-attr get-sxml-item get-sxml-item* 
       get-sxml-tag has-sxml-tag? has-sxml-attr? sxml-drill)

(import "lib/iterate")
(import "lib/filter")

; All special XML syntaxes conveniently start with a <, or an &. Since we
; parse entities in a final pass, this means all interesting syntax starts
; with a <..

(define (parse-data data)
  (pause)
  (define tag-ix (string-find data "<" ))
  (if tag-ix 
    (guard (lambda (err)
             (unless (eq? (error-key err) 'xml-inc)
               (re-error err))
             (define info (error-info err))
             (error 'xml-inc (car info) data))
           (parse-tag (string-read! data tag-ix)
                      data))
    (list data #f "")))

(define (parse-tag pre tag)
    (unless pre (error 'wtf pre tag))
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
      (string-skip! str 9)
      (define cdata-len (string-find str "]]>"))
      (unless cdata-len
        (error 'xml-inc "CDATA section incomplete"))
      (define cdata (string-read! str cdata-len))
      (string-skip! str 3)
      (list cdata
            str))
    #f))

(define (parse-comment str)
  (step "COMMENT" str)
  (if (string-begins-with? str "<!--")
    (begin
      (string-skip! str 4)
      (define end (string-find str "-->"))
      (unless end
        (error 'xml-inc "Comment incomplete"))
      (define cmt (string-read! str end))
      (string-skip! str 3)
      (list (list 'comment cmt)
            str))
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
         (string-skip! str 2)

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
      (string-skip! str 2)

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
      (string-skip! str 2)

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
  (string-skip! str 1)

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
  (when (= ch *stroke-char*)
    (return #t))
  (scanner-drop scan ch)
  #f)
    
(define (spawn-sxml-parser data)
;;; Anatomy of a BEGIN event: <a href='123'>
;;; '(begin tag-name . tag-attrs)
;;; Anatomy of a TAG event: <br />
;;; '(tag tag-name . tag-attrs)
;;; Anatomy of a END event: </a>
;;; '(end tag-name)
;;; Anatomy of a VER event: <?xml version="1.0"?>
;;; '(ver . ver-attrs)
;;; Anatomy of a DECL event: <!DOCTYPE who-really-cares>
;;; '(decl . decl-frags)

  (define out (make-channel))

  (spawn (function (sxml-parse)
           (fail-on-error out 
             (until (empty-string? data) 
                (define r (parse-data data))
                (define head (car r))
                (define item (cadr r))
                (define tail (cadr (cdr r)))
                (unless (string=? head "") (send (list 'cdata head) out))
                (set! data tail)
                (cond
                  ((string? item) (when (> (string-length item) 0)
                                    (send (list 'cdata item) out)))
                  ((pair? item) (send item out))))

             (send '(done) out))))
  
  out)

(define (cddr list)
  (cdr (cdr list)))

(define (spawn-sxml-processor in)
  (define event #f)

  (define (next-event)
    (set! event (wait in)))

  (define (sxml-top)
    (define tag #f)

    (define (await-root)
      (define event (wait in))
      (case (car event)
        ((tag)   (set! tag (sxml-tag event)))
        ((begin) (set! tag (sxml-begin event)))
        ((cdata) (await-root)) ;Any CDATA outside of the root is ignored. 
        ((decl)  (await-root)) ;Our SXML Parser does not bother with decls.
        ((pi)    (await-root)) ;Our SXML Parser assumes XML 1.0, 8-bit encoding.
        ((comment)) ; Comments are not important, here.
        (else (error 'sxml "expected root element" event))))

    (define (await-done)
      (define event (wait in))
      (case (car event)
        ((done)) ;The Done event signals the end of the document.
        ((cdata) (await-done)) ;Any CDATA outside of the root is ignored. 
        ((decl)  (await-done)) ;Our SXML Parser does not bother with decls.
        ((comment)) ; Comments are not important, here.
        (else (error 'sxml "expected document completion" event))))
    
    (await-root)
    (await-done)
    (list '*TOP* tag))

  (define (sxml-tag event)
    (define tag (cadr event))
    (define attrs (cddr event))
    (cons tag (sxml-attr-portion attrs)))

  (define (sxml-attr-portion attrs)
    (when (null? attrs) (return '()))
    (list (cons '* (map sxml-attr-item attrs))))

  (define (sxml-attr-item attr)
    (cons (string->symbol (car attr)) (cdr attr)))
 
  (define (sxml-begin event)
    (define tag (cadr event))
    (define attrs (cddr event))
    (define contents (apply make-tc 
                            (string->symbol tag)
                            (sxml-attr-portion attrs)))
    (forever
      (define event (wait in))
      (case (car event)
        ((tag)   (tc-append! contents (sxml-tag event)))
        ((begin) (tc-append! contents (sxml-begin event)))
        ((cdata) 
         (let ((r (sxml-cdata event)))
           (when r
             (tc-append! contents r))))
        ((decl)) ; Ignore.
        ((comment)) ; Comments are not important, here.
        ((end)   (if (equal? tag (cadr event))
                   (return (tc->list contents))
                   (error (error 'sxml "expected end tag" tag event))))
        (else (error 'sxml "expected element" event)))))

  (define (sxml-cdata event)
    (set! event (strip (cadr event)))
    (if (empty-string? event) #f event))

  (define out (make-channel))

  (spawn (function (sxml-process)
           (fail-on-error out (send (sxml-top) out))))

  out)
    
(define (string->sxml src)
  (error-on-fail
    (wait (spawn-sxml-processor (spawn-sxml-parser src)))))

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
  (unless attr (return #f))
  (define val (cdr attr))
  (if (pair? val) (cdr val) val))

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
  (equal? x value))

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
    ident))

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

(define (sxml->string sxml)
  (define buf (make-string 16384))
  (string-append! buf "<?xml version='1.0'?>")
  
  (define (format-item x)
    (cond ((string? x) (format-cdata x))
          (else (format-tag x))))

  (define (format-tag x)
    (string-append! buf "<")
    (string-append! buf (symbol->string (car x)))
    (for-each format-attr (get-sxml-attrs x))
    (define items (get-sxml-items x))
    (cond
      ((null? items) (string-append! buf " />"))
      (else (string-append! buf ">")
            (for-each format-item items)
            (string-append! buf "</" (symbol->string (car x)) ">"))))

  (define (format-cdata x)
    (if (string-find x "<")
      (string-append! buf "<![CDATA[" x "]]>")
      (string-append! buf x)))

  (define (format-attr x)
    ; attributes must be escaped prior to transmission -- we make a best
    ; effort, here..
    (define val (cdr x)) 
    ; So people can do (* (x 1)); the . is annoying as all hell...
    (if (pair? val) 
      (set! val (car val)))

    (string-append! buf " " (symbol->string (car x)))

    (if (string-find val "'")
      (string-append! buf "=\"" val "\"")
      (string-append! buf "='" val "'")))

  (for-each format-item (get-sxml-items sxml))

  buf)

