(import "lib/test")
(import "lib/cfb")
(import "lib/crypto-filter")

(enable-spot-tests)

(define qp (open-output-string))

(define iv "themagicinitvect")
(define ky (make-aes-key 256))

(define tx (make-cfb ky iv aes-encrypt))
(define rx (make-cfb ky iv aes-encrypt))

(define tp (encrypt-output qp tx cfb-encrypt))
(define rp (decrypt-input qp rx cfb-decrypt))

(define m1 "transmission-001")
(define m2 "now is the time for all good people")
(define m3 "abc")

(s: (send m1 tp)
    (wait rp))
(r: m1)

(s: (send m2 tp)
    (wait rp))
(r: m2)

(s: (send m3 tp)
    (wait rp))
(r: m3)

(send m1 tp)
(send m2 tp)
(send m3 tp)

(s: (wait rp))
(t: m1)

(s: (wait rp))
(t: m2)

(s: (wait rp))
(t: m3)

