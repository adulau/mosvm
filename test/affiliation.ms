(import "lib/test")
(import "mosref/drone")
(import "mosref/console")

(enable-spot-tests)

(define console-ecdh (make-ecdh-key 384))
(define drone-port #f)
(define console-port #f)

(define report (make-channel))
(define control (make-channel))

(define death-rattle (make-channel))
(timeout 5000 death-rattle 'timeout)

(define sync (make-channel))
(spawn (lambda ()
         (set! drone-port (drone-affiliation console-ecdh report control))
         (send 'drone-ready sync)))

(spawn (lambda ()
         (set! console-port (console-affiliation console-ecdh control report))
         (send 'console-ready sync)))

(when (eq? (wait death-rattle sync) 'timeout)
  (error 'test "Failed to affiliate within an acceptable timeout"))

(when (eq? (wait death-rattle sync) 'timeout)
  (error 'test "Failed to affiliate within an acceptable timeout"))

(define drone-xmit (car drone-port))
(define drone-recv (cadr drone-port))

(define console-xmit (car console-port))
(define console-recv (cadr console-port))

(define m1 "alpha")
(define m2 "now is the time for all good people")
(define m3 "")

(send m1 drone-xmit)
(s: (wait death-rattle console-recv))
(r: m1)

(send m2 drone-xmit)
(s: (wait death-rattle console-recv))
(r: m2)

(send m3 drone-xmit)
(s: (wait death-rattle console-recv))
(r: m3)

(send m1 drone-xmit)
(send m2 drone-xmit)
(send m3 drone-xmit)

(s: (wait death-rattle console-recv))
(r: m1)
(s: (wait death-rattle console-recv))
(r: m2)
(s: (wait death-rattle console-recv))
(r: m3)

(send m1 console-xmit)
(s: (wait death-rattle drone-recv))
(r: m1)

(send m2 console-xmit)
(s: (wait death-rattle drone-recv))
(r: m2)

(send m3 console-xmit)
(s: (wait death-rattle drone-recv))
(r: m3)

(send m1 console-xmit)
(send m2 console-xmit)
(send m3 console-xmit)

(s: (wait death-rattle drone-recv))
(r: m1)
(s: (wait death-rattle drone-recv))
(r: m2)
(s: (wait death-rattle drone-recv))
(r: m3)

(send 'close console-xmit)
(s: (wait death-rattle drone-recv))
(r: 'close)

(send 'close drone-xmit)
(s: (wait death-rattle console-recv))
(r: 'close)

