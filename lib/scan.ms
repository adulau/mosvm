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

(module "lib/scan")

(define (make-scanner str)
  (define buf (make-string))
  (string-write buf str)
  (cons #f buf))

(define (scanner-empty? scanner)
  (and (not (car scanner)) 
       (string-empty? (cdr scanner))))

(define (scanner-next scanner)
  (define pre (car scanner))
  (define buf (cdr scanner))
  (if pre 
    (begin 
      (set-car! scanner #f)
      pre)
    (if (string-empty? buf)
      (error 'xml-inc "xml tag incomplete")
      (string-read-byte buf))))

(define (scanner-strip scanner)
  (define pre (car scanner))
  (define buf (cdr scanner))
  (if pre
    (when (memq pre '(32 10 13 9 11))
      (set-car! scanner #f)
      (string-skip-space buf))
    (string-skip-space buf)))

(define (scanner->string scanner)
  (define pre (car scanner))
  (define str (cdr scanner))
  (if pre (string-append pre str)
          str))

(define (scanner-drop scanner ch)
  (set-car! scanner ch))

(export make-scanner scanner-empty? scanner-next scanner-strip scanner->string
        scanner-drop)
