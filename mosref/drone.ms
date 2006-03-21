; Copyright (C) 2006, Ephemeral Security, LLC
; 
; This library is free software; you can redistribute it and/or modify it 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
; 
; This library is distributed in the hope that it will be useful, but WITHOUT 
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
; FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License 
; for more details.
; 
; You should have received a copy of the GNU Lesser General Public License 
; along with this library; if not, write to the Free Software Foundation, 
; Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 

(module "mosref/drone")

(import "lib/cfb")
(import "lib/fuse")
(import "lib/crypto-port")
(import "lib/freeze")
(import "lib/format")

(import "mosref/base")

(define (drone-affiliation console-ecdh port)
  ;;;TODO: Configure timeout.

  (define drone-iv (make-iv))
  (define drone-ecdh (make-ecdh-key 384)) 
  (define aes-key (make-aes-key 256 
                                (ecdh-shared-secret drone-ecdh console-ecdh)))

  ;;; Drone --> Console, via plaintext, Dp
  (write (export-public-ecdh drone-ecdh) port)

  ;;; Drone --> Console, via KK, DD
  (write (aes-encrypt aes-key drone-iv) port)

  ;;; Console --> Drone, via KK, CC
  (define console-iv (aes-decrypt aes-key (read 16 port)))
 
  (define drone-key (make-cfb aes-key drone-iv aes-encrypt))
  (define console-key (make-cfb aes-key console-iv aes-encrypt))
  
  (define drone-port (encrypt-output port drone-key cfb-encrypt))
  (define console-port (decrypt-input port console-key cfb-decrypt))

  ;;; Drone --> Console, via RK, CC
  (write console-iv drone-port)

  ;;; Console --> Drone, via CK, DD
  (unless (string=? (read console-port) drone-iv)
    (error 'aff "the console failed to confirm affiliation"))

  (fuse-ports console-port drone-port))

(define (drone-repl port)
  (define result (make-buffer))
  (define (format-context context)
    (string-append "("
                   (apply string-join 
                          " "
                          (symbol->string (function-name (car context)))
                          (map value->string (cdr context)))
                   ")"))
  (define (format-error-info info)
    (cond ((null? info) "")
          ((string? (car info)) (car info))
          (else (apply string-join " " (map value->string info)))))

  (define (fail-result error)
    (freeze `(fail ,(error-key error)
                   ,(format-error-info (error-info error))
                   ,(map format-context (cdr (error-context error))))))
  (define (succ-result result)
    (freeze `(succ ,result)))
  ;;; TODO: Add a tagging port for repl output.
  ;;; TODO: Add a caching port for repl input.
  (until (closed? port)
    (define message (read port))

    (unless (eof-object? message)
      (write (guard fail-result (succ-result ((thaw message)))) 
             port)))) 

(export drone-repl drone-affiliation)

