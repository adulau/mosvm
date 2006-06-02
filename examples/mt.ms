(define (show (<pair> p))
  (if (null? p) 
    (show "'()")
    (begin
      (show "(")
      (show (car p))
      (show ".")
      (show (cdr p))
      (show ")"))))

(show (list 1 2 3))
(newline)
;;; MOSVM2
;;; MOSVM2
