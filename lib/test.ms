; Copyright (c) 2006, Scott W. Dunlop <sdunlop@users.sourceforge.net>
; All rights reserved.
; 
; under the terms of the GNU Lesser General Public License, version 2.1
; as published by the Free Software Foundation.
;     * Redistributions of source code must retain the above copyright 
;       notice, this list of conditions and the following disclaimer.
;     * Redistributions in binary form must reproduce the above copyright 
;       notice, this list of conditions and the following disclaimer in the 
;       documentation and/or other materials provided with the distribution.
;     * The names of its contributors may not be used to endorse or promote     
;       products derived from this software without specific prior written 
;       permission.
; 
; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
; AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
; ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
; LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
; CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
; SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
; INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
; CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
; ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
; POSSIBILITY OF SUCH DAMAGE.

(export "lib/test")

(define *spot-test?* #f)
(define *spot-s* #f)
(define *spot-v* #f)

(define *spot-ect* 0)

(define (spot-error . lines)
  (set! *spot-ect* (+ *spot-ect* 1))
  (let ((lines (cons (cons "s:  " *spot-s*) 
                      lines)))
    (for-each (lambda (line) 
                (show "    ")
                (for-each (lambda (phrase)
                            (show phrase))
                          line)
                (newline))
              lines)))

(define (enable-spot-tests) (set! *spot-test?* #t))

(define (disable-spot-tests) (set! *spot-test?* #f))

(define (do-s expr fn)
  (set! *spot-s* expr)
  (set! *spot-v* (fn)))

(define (do-r expr fn)
  (let ((x (fn)))
    (if (not (equal? x *spot-v*))
      (spot-error (cons "r:  " expr)
                  (list "sv: " *spot-v*)
                  ;(cons "sv: " (if (pair? *spot-v*) (list (length *spot-v*)
                  ;                                        "/"
                  ;                                        *spot-v*)
                  ;                                  (list *spot-v*)))
                  (list "rv: " x)))))

(define (do-t expr fn)
    (let ((x (fn *spot-v*)))
          (if (not x)
            (spot-error (cons "t:  " expr)))))

(define (spot-report)
  (if (> *spot-ect* 0)
    (begin
      (show "Test cases failed:")
      (show *spot-ect*)
      (newline))
    (begin
      (show "All tests passed.")
      (newline))))

(define (main . ignored)
  (spot-report)
  (= *spot-ect* 0))
