(module "mosref/brutal")
(import "lib/with-io")

; Brutally aggressive, brutally simple, or just a brutal's idea of a port
; scanner..

(define (brutal hosts ports lapse)
  (define (brutal/host host)
    (define (brutal/host-port port)
      (define conn (guard (function (signal-refusal x)
                            ;(send (list 'refused host port))
                            #f)
                          (tcp-connect addr port)))

      (unless conn (return))

      (define timer (timeout lapse (output conn) 'timeout))

      (define evt (wait conn))

      (when (eq? evt 'timeout) 
        (send 'close conn)
        (return))
    
      (cancel-timeout timer)
      (send (list conn host port)))

    (define addr host)

    (when (string? addr)
      (set! addr (guard (lambda (x) #f) (resolve-addr host)))
      (unless addr
        (return (send (list 'not-found host)))))
        
    (if (list? ports)
      (for-each brutal/host-port ports)
      (brutal/host-port host ports)))

  (with-output (make-channel)
    (spawn (function (brute) 
             (if (list? hosts)
               (for-each brutal/host hosts)
               (brutal/host hosts))
  
             (send (list 'done hosts ports lapse))))))

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

