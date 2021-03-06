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

(define (read-data-file path)
  (define file (open-file path "r"))
  (define data (read-file file *max-int*))
  (close-file file)
  data)

(define (write-data-file path content)
  (define file (open-file path "wct"))
  (write-file file content)
  (close-file file))

(define (read-lisp-file path)
  (string->exprs (read-data-file path)))

(define (path-join . items)
  (apply string-join *path-sep* items))

(define (convert-path path)
  (apply path-join (string-split* path "/")))

(export path-join convert-path)

(export read-data-file write-data-file read-lisp-file path-join convert-path)

