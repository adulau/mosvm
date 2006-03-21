(import "lib/test")
(import "lib/fuse")
(import "mosref/drone")
(import "mosref/console")

(enable-spot-tests)

(define bp1 (open-queue-port))
(define bp2 (open-queue-port))

(define drone-port (fuse-ports bp1 bp2))
(define console-port (fuse-ports bp2 bp1))

(spawn (lambda () (drone-repl drone-port)))

(s: (drone-exec '((+ 1 1)) console-port))
(r: '(succ 2))

(s: (drone-exec '((/ 1 0)) console-port))
(r: '(fail bad-args 
           "attempted divide by zero" 
           ("(/ 1 0)")))

