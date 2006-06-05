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

(module "lib/crypto-filter")

(export decrypt-filter encrypt-filter)

;; This filter will accept ciphertext, and will render blocks of plaintext.
;;TODO: This needs to forward errors as fail messages.
(define (decrypt-filter in key decrypt)
  (define block-size (key-block-size key))
  (define out (make-channel))

  (define add-cipher-text
    (if block-size
      (let ((cipher-text (make-string)))
        (function (decrypt-cipher-blocks data)
          (string-append! cipher-text data)
          (while (> (string-length cipher-text) block-size)
            (send (decrypt (string-read cipher-text block-size)) out))))
      (function (decrypt-stream-cipher data)
        (send (decrypt key data) out))))

  (spawn (function (decrypt-input-loop)
            (forever
              (define evt (wait in))
              (if (string? evt) (add-cipher-text evt)
                                (send evt out)))))
  out)

;; This filter will accept plaintext, and will render a string of ciphertext.
;;TODO: This needs to forward errors as fail messages.
(define (encrypt-filter port key encrypt)
  (define block-size (key-block-size key))
  (define out (make-channel))

  (define encrypt-cipher-text
    (if block-size
        (function (encrypt-blocks data)
          (define work (copy-string data))
          (define data (make-string))
          (until (empty-string? work)
            (string-append! data (encrypt key (string-read! work block-size))))
          (send data out))
        (function (encrypt-stream data)
          (send (encrypt key data) out))))

  (spawn (function (encrypt-output-loop)
            (forever
              (define evt (wait in))
              (if (string? evt) (encrypt-cipher-text evt)
                                (send evt out)))))
  out)

