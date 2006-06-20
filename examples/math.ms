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
(import "lib/trace")

(define-flow (math)
  (flowlet ((a query "a")
            (b query "b")
            (path path))
    
    (set! a (false-on-error (string->integer a)))
    (set! b (false-on-error (string->integer b)))

    (html-ok 
      (if (and a b)
        `(html (body (h3 "The answer is " ,(format (+ a b)))))
        `(html (body (form (* (action ,path) 
                              (method "post"))
                           (input (* (name "a")
                                     (value ,(format (or a 0)))))
                           (b "+")
                           (input (* (name "b")
                                     (value ,(format (or b 0)))))
                           (input (* (type "submit")
                                     (value "="))))))))))

(define portno (random-integer 8000 9000))
(print (string-append "Listening on " (format portno) *line-sep*))

(spawn-flow portno (math))
