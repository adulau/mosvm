(define-record-type point
                    (make-point x)
                    point?
                    (x point-x)
                    (y point-y set-point-y!))

(define x (make-point 111))
(set-point-y! x 222)
(show (list (point? x)
            (record? x)
            (point-x x)
            (point-y x)))
;;; MOSVM2
;;; MOSVM2
