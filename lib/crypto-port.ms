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

(import "lib/trace")
(import "lib/format")

;;; Provides a wrapper for other ports that will automatically break
;;; transmissions into blocks, and transmit / receive using a key. 

(module "lib/crypto-port")

(export decrypt-input encrypt-output)

;;; TODO: This will only read one block at a time.

(define (decrypt-input port key decrypt)
  (define block-size (key-block-size key))

  (define ciphertext (make-buffer))

  (define plaintext (make-buffer))

  (define (more-ciphertext)
    (when (closed? port)
      (error 'io "port closed in the middle of a ciphertext read"))
    (write-buffer ciphertext (read port)))

  (define (more-plaintext)
    (when (buffer-empty? ciphertext)
      (more-ciphertext))
    (write-buffer plaintext (decrypt key (read-buffer ciphertext 
                                                      block-size))))

  (define (fill-plaintext amount)
    (until (>= (buffer-length plaintext) amount)
      (more-plaintext)))

  (define (read-message ignored)
    ;; TODO: Put a common sense barrier in this.
    (fill-plaintext 4)
    (define message-length (read-buffer-quad plaintext))
    (define padding-length (remainder (+ 4 message-length) block-size))
    (if (> padding-length 0)
      (set! padding-length (- block-size padding-length))
      (set! padding-length #f))

    (fill-plaintext message-length)
    (define r (read-buffer plaintext message-length))

    (when padding-length (buffer-skip plaintext padding-length))

    r)

  (make-port read-message
             (and (output-port? port) (lambda (p d) (write d port)))
             (lambda (p) (close port))
             #f))

(define (encrypt-output port key encrypt)
  (define block-size (key-block-size key))
  (define plaintext (make-buffer))
  (define ciphertext (make-buffer))
  (define (write-message ignored message)
    (define message-length (string-length message))
    (define padding-length (remainder (+ 4 message-length) block-size))

    (if (> padding-length 0)
      (set! padding-length (- block-size padding-length))
      (set! padding-length #f))

    (write-buffer-quad plaintext (string-length message))
    (write-buffer plaintext message)
    (when padding-length
      (write-buffer plaintext (random-string padding-length)))

    (until (buffer-empty? plaintext)
      (write-buffer ciphertext (encrypt key 
                                        (read-buffer plaintext block-size))))
    (write (read-buffer ciphertext) port))

  (make-port (and (input-port? port) (lambda (p) (read p)))
             write-message
             (lambda (p) (close port))
             #f))

