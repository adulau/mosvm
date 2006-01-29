(define (for-each fn . lists)
  (until (memq '() lists)
    (apply fn (map-car lists))
    (set! lists (map-cdr lists))))

(for-each cons
          '(x y z)
          '(1 2 3))

(for-each (lambda (s i) (show (cons s i))) 
          '(x y z) 
          '(1 2 3))

