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

(import "lib/module")
(import "lib/format")

(define (main module)
  (define exports (code-exports module))

  (define (wikify-list data)
    (define output (make-buffer))

    (define (wikify-list-item item)
      (string-write output "* {")
      (string-write output item)
      (string-write output "}")
      (string-write output *line-sep*))
     
    (for-each wikify-list-item data)
    (buffer->string output))

  (define (sort-list data)
    (set->list (apply set data)))

  (write "! Imports:")
  (newline)

  (write (wikify-list (sort-list (code-imports module))))
  (newline)

  (write "! Exports:")
  (newline)
  
  (write (wikify-list (sort-list (map symbol->string (code-exports module)))))

  (newline))

