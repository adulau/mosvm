(export "lib/repl")

(import "lib/compile")
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
(define (repl)
  (define stdin (open-stdin))
  (define stdout (open-stdout))
  (define data #f)
  (define done #f)
  (until done
    (newline)
    (file-write stdout ">> ") 
    (guard il-traceback
      (set! data (file-read stdin 1024))
      (if (> (string-length data) 0)
        (begin
          (set! data (string->exprs data))
          (set! data (compile data))
          (set! data (optimize data))
          (set! data (assemble data))
          (set! data (data))
          (file-write stdout ":: ") 
          (show data))
        (begin
          (show "Bye!")
          (newline)
          (set! done #t))))))
