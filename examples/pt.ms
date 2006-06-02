(define-record-type <point>
                    (make-point x y)
                    point?
                    (x point-x set-point-x!)
                    (y point-y set-point-y!))

(show "marker")
(newline)

(define (show (<point> p)) 
  (show "(x: ")
  (show (point-x p))
  (show " y: ")
  (show (point-y p))
  (show ")"))

(define p1 (make-point 111 222))

(show "Point 1: ")
(show p1)
(newline)

;;; MOSVM2
;;; MOSVM2
