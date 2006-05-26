
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

(module "lib/record")
(import "lib/object")

;;; (define-macro (define-record-type record-name 
;;;                                   make-proto pred-name . record-fields)
;;;   `(define-class ,record-name <object> ,make-proto ,pred-name 
;;;                  ,@record-fields))

(set-macro! define-record-type 
            (lambda (record-name make-proto pred-name . record-fields)
              (define tc (make-tc))
              (tc-splice! tc (list 'define-class record-name '<object>))
              (tc-splice! tc (make-proto pred-name))
              (tc-splice! tc record-fields)
              (tc->list tc)))

(export define-record-type)
