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

(module "mosref/ec-stage")

; The engagement configuration stage.

(define *cidr-rx* (make-regex "^(.+)/([0-9]+)$"))
(define *hrange-rx* (make-regex "^([0-9.]+)[ \t]*-[ \t]*([0-9.]+)$"))
(define *prange-rx* (make-regex "^([0-9]+)[ \t]*-[ \t]*([0-9]+)$"))

(define (parse-net-host src)
  (list 'host src))

(define (parse-net-seq src)
  (define res (match-regex *hrange-rx* src))
  (unless res (return #f))
  (list 'host-range (car res) (cadr res)))

(define (parse-net-cidr src)
  (define res (match-regex *cidr-rx* src))
  (unless res (return #f))
  (list 'cidr (car res) (string->integer (cadr res))))

(define (parse-host-range host-range)
  (or (parse-net-cidr host-range)
      (parse-net-seq host-range)
      (parse-net-host host-range)))

(define (parse-port-seq src)
  (define res (match-regex *prange-rx* src))
  (unless res (return #f))
  (list 'port-range (string->integer (car res)) (string->integer (cadr res))))

(define (parse-port src)
  (string->integer src))

(define (parse-port-range port-range)
  (or (parse-port-seq port-range)
      (parse-port port-range)))

(define (engage host-spec port-spec)
  (define host-ranges 
    (map parse-host-range 
         (map strip (string-split* host-spec ","))))

  (define port-ranges
    (map parse-port-range
         (map strip (string-split* port-spec ","))))
  
  (list 'engage host-ranges port-ranges))
 
