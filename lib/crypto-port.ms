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

(export decrypt-input encrypt-output)

;;; TODO: This will only read one block at a time.

(define (decrypt-input port key decrypt)
  (define block-size (key-block-size key))
  (define read-buf (make-buffer))
  (define (load-buffer)
    (while (< (buffer-length read-buf) block-size)
      (when (closed? port)
        (error 'io "port closed in the middle of a cipher read"))
      (write-buffer read-buf (read port))))
  (define (fetch-block)
    (load-buffer)
    (read-buffer read-buf 16))

  (make-port (lambda (p) (decrypt key (fetch-block)))
             (and (output-port? port) (lambda (p d) (write d port)))
             (lambda (p) (close port))
             #f))

;;; TODO: This will cause some trailing garbage with transmission that have
;;;       lengths that are not multiples of block-size.

(define (encrypt-output port key encrypt)
  (define block-size (key-block-size key))
  (define write-buf (make-buffer))
  (make-port (and (input-port? port) (lambda (p) (read p)))
             (lambda (p d)
               (write-buffer write-buf d)
               (until (buffer-empty? write-buf)
                  (when (closed? port)
                    (error 'io "port closed in the middle of a cipher write"))
                  (write (encrypt key (read-buffer write-buf 16))
                         port)))))

