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

;;; Provides a wrapper for other ports that will automatically break
;;; transmissions into blocks, and transmit / receive using a key. 

(module "lib/crypto-port")

(import "lib/port")

(export decrypt-input encrypt-output)

;;; TODO: This will only read one block at a time.

(define (decrypt-input port key decrypt)
  (define block-size (key-block-size key))
  (define plaintext (make-string))
  (define body-length #f)
  (define message-body #f)

  (define (read-block) 
    (define data (read block-size port))
    (if (eof-object? data)
      (error 'eof)
      (string-write plaintext (decrypt key data))))

  (define (flush-plaintext)
    (flush-string plaintext))
 
  ;;;TODO: Needs to eof on eof.
  (define (read-header)
    (read-block)
    (set! body-length (string-read-word plaintext))
    (flush-plaintext))

  ;;;TODO: Needs to throw an exception on eof.
  (define (read-body)
    (until (>= (string-length plaintext) body-length)
      (read-block))
    (set! message-body (string-read plaintext body-length))
    (flush-string plaintext))

  ;;;TODO: Needs checksums.
  (define (check-body) #t)

  (define (read-message ignored also-ignored)
    (guard (lambda (e)
             (if (eq? (error-key e) 'eof)
               *eof*
               (re-error e)))
      (read-header)
      (read-body)
      (check-body)
      message-body))
    
  (make-port read-message
             (and (output-port? port) (lambda (p d) (write d port)))
             (lambda (p) (close port))
             #f))

(define (encrypt-output port key encrypt)
  (define block-size (key-block-size key))
  (define plaintext (make-string))
  (define ciphertext (make-string))

  (define message-body #f)
  (define message-length #f)

  (define (write-block)
    (string-write ciphertext (encrypt key (string-read plaintext block-size))))

  (define (write-header)
    (string-write-word plaintext message-length)
    (write-block))

  (define (write-body)
    (string-write plaintext message-body)
    (until (empty-string? plaintext) (write-block)))

  (define (write-message ignored message)
    (set! message-length (string-length message))
    (set! message-body message)
    (write-header)
    (write-body)
    (write (string-read ciphertext) port))

  (make-port (and (input-port? port) (lambda (p) (read p)))
             write-message
             (lambda (p) (close port))
             #f))

