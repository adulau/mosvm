(let ((f (file-open "lib/core.ms" "r")))
  (show (file-read f 16))
  (show "...")
  (newline)
  (set! f #f))

(list 'a 'b 'c 'd 'e 'f 'g 'h); overwrites the data stack. 
(gc-now);if trace is on, a file finalization message will be displayed.
  
;;; MOSVM2
;;; MOSVM2
