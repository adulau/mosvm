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

(import "lib/http-flow")
(import "lib/iterate")
(import "lib/trace")

(define (constrain-path path roots)
  (unless (any (lambda (root) (string-begins-with? path root)) roots)
    (error 'http (string-append "path " 
                                (format path) 
                                " beyond constraints")
           404))
 
  (when (string-find path "..")
    (error 'http "path element not permitted" 404 path)))

(define (read-module-text path)
  (guard (lambda (orig)
           (error 'http (string-append "could not find " (format path)) 404))
    (read-data-file (find-module-file (string-append (convert-path path)
                                                     ".ms")))))

(define (module-list-item path)
  `((a (* (href ,(string-append "/" path)))
          ,path)
    " "))

(define (symbol-list-item symbol)
  `(,(symbol->string symbol) " "))

(define (module-display-page recent module)
  (define text    (read-module-text module))
  (define source  (string->exprs text))
  (define imports (code-imports source))
  (define exports (code-exports source))
  
  `(html (* (xmlns "http://www.w3.org/1999/xhtml")
            (xml:lang "en"))
         (head (title ,module)
               (link (* (rel "stylesheet")
                        (href "/style.css")
                        (type "text/css"))))
         (body (h2 ,module)
               (h3 "Recent History:")
               (p ,@@(map module-list-item recent))
               (h3 "Imports:")
               (p ,@@(map module-list-item imports))
               (h3 "Exports:")
               (p ,@@(map symbol-list-item exports))
               (h3 "Source:")
               (pre ,text))))

(define *tracker-stylesheet*
  (string-append "p, pre{ margin:0; margin-left: 15px; padding:0; };"))

(define-flow (tracker . paths)
  (define history (make-tc))

  (forever
    (print "Forever begins now.\n")
    (flowlet ((path path))

    (if (string-begins-with? path "/")
      (string-skip! path 1))
    
    (if (string=? path "style.css")
      (css-ok *tracker-stylesheet*)
      (begin
        (constrain-path path paths)
        (xml-ok (module-display-page (tc->list history) path))
        (print "Page returned.\n")
        (tc-append! history path))))))

(define portno (random-integer 8000 9000))
(print (string-append "Listening on " (format portno) *line-sep*))

(spawn-flow portno (tracker "lib" "examples" "core" "mosref")) 
