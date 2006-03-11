(import "lib/test")
(import "lib/cfb")
(import "lib/crypto-port")

(enable-spot-tests)

(define qp (open-output-string))

(define iv "themagicinitvect")
(define ky (make-aes-key 256))

(define tx (make-cfb ky iv aes-encrypt))
(define rx (make-cfb ky iv aes-encrypt))

(define tp (encrypt-output qp tx cfb-encrypt))
(define rp (decrypt-input qp rx cfb-decrypt))

(define m1 "transmission-001")
(define m2 "transmission-002")
(define m3 "transmission-003")

(s: (write m1 tp)
    (read rp))
(r: m1)

(s: (write m2 tp)
    (read rp))
(r: m2)

(s: (write m3 tp)
    (read rp))
(r: m3)

(write m1 tp)
(write m2 tp)
(write m3 tp)

(s: (read rp))
(t: m1)

(s: (read rp))
(t: m2)

(s: (read rp))
(t: m3)

