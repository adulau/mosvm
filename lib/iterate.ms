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
;  

(module "lib/iterate")

;;; TODO: lib/iterate
;;; for-each, map, find-tail, list-index, any, filter, fold and find from SRFI-1
(define (filter fn list)
  (define tc (make-tc))
  (until (null? list)
         (define it (car list))
         (if (fn it)
           (tc-append! tc it))
         (set! list (cdr list)))
  (tc->list tc))

(define filter! filter)

(define (fold fn acc . lists)
  (until (memq '() lists)
         (set! acc (apply fn (append (map-car lists) (list acc))))
         (set! lists (map-cdr lists)))
  acc)

(define (for-each fn . lists)
  (until (memq '() lists)
         (apply fn (map-car lists))
         (set! lists (map-cdr lists))))

(define (map fn . lists)
  (define tc (make-tc))
  (until (memq '() lists)
         (tc-append! tc (apply fn (map-car lists)))
         (set! lists (map-cdr lists)))
  (tc->list tc))

(define (find-tail fn list)
  (define done #f)
  (until done 
    (cond ((null? list)    (set! done #t))
          ((fn (car list)) (set! done #t))
          (else (set! list (cdr list)))))
  (if (null? list)
    #f
    list))

(define (list-index fn . lists)
  (define done #f)
  (define index 0)
  (until done 
         (cond ((memq '() lists) (set! index #f)
                                 (set! done #t))
               ((apply fn (map-car lists)) (set! done #t))
               (else (set! index (+ index 1))
                     (set! lists (map-cdr lists)))))
  index)

(define (find fn list)
  (set! list (find-tail fn list))
  (if list (car list) #f))

(define (any fn . lists)
  (define done #f)
  (define found #f)
  (until done
         (cond ((memq '() lists) 
                (set! done #t))
               ((apply fn (map-car lists)) 
                (set! found #t)
                (set! done #t))
               (else 
                 (set! lists (map-cdr lists)))))
  found)

(export filter filter! fold for-each map find-tail list-index find any)

