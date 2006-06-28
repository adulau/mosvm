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

(module "lib/defdb")
(import "lib/clue")

(export define-table define-foc define-field define-new)

(define-macro (define-table type)
  `(begin
     (define ,(make-symbol 'table: type) (new-clue-db))
     (define ,(make-symbol 'find- type)
       (find-clue ,(make-symbol 'table: type)))))

(define-macro (define-foc type . fields)
  (define fl (map (lambda (fn) (list fn fn))
                  fields))

  `(define (,(make-symbol 'foc- type) ,@fields)
     (define record (find-clue ,(make-symbol 'table: type) ,@fl))
     (if (null? record)
         (put-clue ,(make-symbol 'table: type) ,@fl)
         (car record))))

(define-macro (define-new type . fields)
  (define fl (map (lambda (fn) (list fn fn))
                  fields))

  `(define (,(make-symbol 'new- type) ,@fields)
     (put-clue ,(make-symbol 'table: type) ,@fl)))

(define-macro (define-field type field)
  `(begin
     (define (,(make-symbol type '- field) record)
       (get-clue record ,field))
     (define (,(make-symbol 'set- type '- field '!) record value)
       (set-clue record (,field value)))
     (define (,(make-symbol 'find- type '- 'by- field) value)
       (find-clue ,(make-symbol 'table: type) (,field value)))))

