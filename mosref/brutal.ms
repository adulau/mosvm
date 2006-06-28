(module "mosref/brutal")

; Brutally aggressive, brutally simple, or just a brute's idea of a port
; scanner..

(define (brute hosts ports lapse)
  (define (brute/host host)
    (define (brute/host-port port)
      (define conn (guard (function (signal-refusal x)
                            ;(send (list 'refused host port))
                            #f)
                          (tcp-connect addr port)))

      (unless conn (return))

      (timeout lapse (output conn) 'timeout)

      (define evt (wait conn))
      (when (eq? evt 'timeout) (return))

      (send (list (wait conn) host port))
      (send 'close conn))

    (define addr host)

    (when (string? addr)
      (set! addr (guard (lambda (x) #f) (resolve-addr host)))
      (unless addr
        (return (send (list 'not-found host)))))
        
    (if (list? ports)
      (for-each brute/host-port ports)
      (brute/host-port host ports)))

  (if (list? hosts)
    (for-each brute/host hosts)
    (brute/host hosts))
  
  (send (list 'done hosts ports lapse)))

(define (integer-range first last)
  (when (> first last)
    (define temp last)
    (define last first)
    (define first temp))

  (define tc (make-tc))

  (until (>= first last)
    (tc-append! tc first)
    (set! first (+ first 1)))

  (tc->list tc))

(define (port-range first last)
  (integer-range first last))

(define (addr-range first last)
  (integer-range first last))

(define (cidr base mask)
  (addr-range base (| base (- (<< 1 (- 32 mask)) 1))))

(define (ipv4 q1 q2 q3 q4)
  (+ (<< q1 24)
     (<< q2 16)
     (<< q3  8)
     q4))

