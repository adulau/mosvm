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
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.


(export "lib/repl")
(import "lib/compile")

(define (repl)
  (define data #f)
  (define done #f)

  (until done
    (newline) 
    (write-descr *console* ">> ")
    (set! data (read-descr *console*))
    (if (> (string-length data) 0)
      (guard il-traceback
        (set! data (string->exprs data))
        (set! data (compile data))
        (set! data (optimize data))
        (set! data (assemble data))
        (set! data (data))
        (write-descr *console* ":: ") 
        (show data))
      (begin
        (show "Bye!")
        (newline)
        (set! done #t)))))

