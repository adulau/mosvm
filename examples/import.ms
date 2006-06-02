(define import #f)
(define reload #f)

(let ((*basedir* (getcwd))
      (*imports* '()))

  (set! import (lambda (key)
                 (unless (assq key *imports*)
                   (let ((path (string-append *basedir* "/" key ".mo")))
                     (load-mo path)
                     (set! *imports* (cons (cons key path) *imports*))))))

  (set! reload (lambda (key)
                 (let ((item (assq key *imports*)))
                   (if item
                     ((load-mo (cdr item)))
                     (import key))))))

(define (load-mo path)
  ((thaw-file path)))

(import "examples/l123")
;;; MOSVM2
;;; MOSVM2
