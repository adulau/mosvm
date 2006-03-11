(import "lib/test")

(enable-spot-tests)

(define m "The quick brown fox jumped over the lazy dog")
(s: (base64-encode m))
(r: "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2c=")
(t: (string=? (base64-decode _) m))

(s: (make-aes-key 256))
(t: (aes-key? _))
(t: (eq? (key-size _) 256))
(t: (eq? (key-block-size _) 16))

(define k (make-aes-key 256 "aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkk"))
(define p "the quick brown ")
(define c "+QMup9bKGCBpCJb0552tYw==")

(s: (base64-encode (aes-encrypt k p)))
(r: c)

(s: (aes-decrypt k (base64-decode c)))
(r: p)

(s: (xor-string "alpha" "maskmaskmask"))
(t: (= (string-length _) 5))
(t: (not (string=? _ "alpha")))
(t: (string=? (xor-string _ "maskmask") "alpha"))
(t: (not (string=? (xor-string _ "askmask") "alpha")))

(s: (make-ecdh-key 256))
(t: (ecdh-key? _))
(t: (ecdh-private-key? _))
(t: (not (ecdh-public-key? _)))

(define c (make-ecdh-key 256))
(define d (make-ecdh-key 256))

(s: (import-ecdh (export-private-ecdh c)))
(t: (ecdh-key? _))
(t: (ecdh-private-key? _))
(t: (not (ecdh-public-key? _)))

(s: (import-ecdh (export-public-ecdh c)))
(t: (ecdh-key? _))
(t: (ecdh-public-key? _))
(t: (not (ecdh-private-key? _)))

(define cp (import-ecdh (export-public-ecdh c)))
(define dp (import-ecdh (export-public-ecdh d)))
(define cq c)
(define dq d)

(s: (ecdh-shared-secret cq dp))
(r: (ecdh-shared-secret dq cp))
(t: (string? _))

