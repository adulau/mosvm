(define (show-all . l)
  (until (null? l)
    (show (car l))
    (set! l (cdr l))))

(show-all 1 2 3)
