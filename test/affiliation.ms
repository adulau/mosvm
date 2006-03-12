(import "lib/test")
(import "lib/fuse")
(import "mosref/control")

(enable-spot-tests)

(define console-ecdh (make-ecdh-key 384))
(define drone-port #f)
(define console-port #f)

(define bp1 (open-buffer-port))
(define bp2 (open-buffer-port))

(spawn (lambda ()
         (set! drone-port (drone-affiliation console-ecdh 
                                             (fuse-ports bp1 bp2)))))

(spawn (lambda ()
         (set! console-port (console-affiliation console-ecdh 
                                                 (fuse-ports bp2 bp1)))))

(until (and console-port drone-port) 
       (pause))

(define m1 "alpha")
(define m2 "now is the time for all good people")
(define m3 "")

(write m1 drone-port)
(s: (read console-port))
(r: m1)

(write m2 drone-port)
(s: (read console-port))
(r: m2)

(write m3 drone-port)
(s: (read console-port))
(r: m3)

(write m1 drone-port)
(write m2 drone-port)
(write m3 drone-port)

(s: (read console-port))
(r: m1)
(s: (read console-port))
(r: m2)
(s: (read console-port))
(r: m3)

(write m1 console-port)
(s: (read drone-port))
(r: m1)

(write m2 console-port)
(s: (read drone-port))
(r: m2)

(write m3 console-port)
(s: (read drone-port))
(r: m3)

(write m1 console-port)
(write m2 console-port)
(write m3 console-port)

(s: (read drone-port))
(r: m1)
(s: (read drone-port))
(r: m2)
(s: (read drone-port))
(r: m3)

