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

(module "lib/compile")
(import "lib/lib")

(export compile)

(define-record-type context
                    (make-context reality parent symbols slots rules exports)
                    context?
                    (reality context-reality)
                    (parent  context-parent)
                    (symbols context-symbols set-context-symbols!)
                    (slots context-slots set-context-slots!)
                    (rules context-rules set-context-rules!)
                    (exports context-exports set-context-exports!))
    
(define (add-context-slot! context slot)
  (set-context-slots! context (append! (context-slots context) (list slot))))

(define (add-context-symbol! context symbol)
  (set-context-symbols! context (cons symbol (context-symbols context))))

(define (add-context-rule! context key function)
  (dict-set! (context-rules context) key function))

(define (find-context-rule context key)
  (if context
    (let ((rule (dict-ref (context-rules context) key)))
      (if rule 
        rule
        (find-context-rule (context-parent context) key)))
    #f))

(define (add-context-binding! local symbol)
  (add-context-slot! (find-actual-context local)
                     (cons symbol local))
  (add-context-symbol! local symbol))

(define (make-slots context symbols)
  (map (lambda (symbol) 
         (cons symbol context))
       symbols))

(define (make-actual-context parent symbols)
  (let ((new-context (make-context #t parent symbols #f (dict) #f)))
    (set-context-slots! new-context 
                        (make-slots new-context symbols))
    new-context))

(define (make-top-context)
  (define top (make-actual-context #f '()))
  (set-context-rules! top (apply dict (mosvm-syntax)))
  top)

(define (is-top-context? context)
  (not (context-parent context)))
                
(define (is-actual-context? context)
  (context-reality context))

(define (is-virtual-context? context)
  (not (context-reality context)))

(define (is-exported? symbol context)
  (if (context-exports context)
    (memq symbol (context-exports (find-top-context context)))
    #t))

(define (context-slot-count context)
  (length (context-slots context)))

(define (find-top-context context)
  (cond ((not context) #f)
        ((is-top-context? context) context)
        (else (find-top-context (context-parent context)))))

(define (find-actual-context context)
  (cond
    ((not context) #f)
    ((is-actual-context? context) context)
    (else (find-actual-context (context-parent context)))))

(define (make-virtual-context parent symbols)
  (let ((new-context (make-context #f parent symbols #f (dict) #f))
        (actual-context (find-actual-context parent)))
    (set-context-slots! actual-context
                        (append (context-slots actual-context)
                                (make-slots new-context symbols)))
    new-context))

(define (context-defines-symbol? context symbol)
  (if (memq symbol (context-symbols context)) 
      #t #f))

(define (context-slot-index context slot-context slot-symbol)
  (list-index (lambda (x) (and (eq? (car x)
                                    slot-symbol)
                               (eq? (cdr x)
                                    slot-context)))
              (context-slots context)))

(define (context-symbol-addr context symbol)
  (define result #f)
  (define actuals 0)
  (while context
    (cond ((context-defines-symbol? context symbol)
           (set! result 
             (list actuals
                   (context-slot-index (find-actual-context context)
                                       context
                                       symbol)))
           (set! context #f))
          ((is-actual-context? context)
           (set! context (context-parent context))
           (set! actuals (+ actuals 1)))
          (else
           (set! context (context-parent context)))))
  result)

(define *mosvm-syntax*
  (list 
    (cons 'export (lambda any '(begin)))
    (cons 'with-input-port
          (lambda (port . rest)
            `(let ((%old-input (current-input-port)))
               (set-process-input! ,port)
               (guard (lambda (%e) 
                        (set-process-input! %old-input)
                        (re-error %e))
                 (define %result (begin ,@rest))
                 (set-process-input! %old-input)
                 %result))))
    (cons 'with-output-port
          (lambda (port . rest)
            `(let ((%old-output (current-output-port)))
               (set-process-output! ,port)
               (guard (lambda (%e) 
                        (set-process-output! %old-output)
                        (re-error %e))
                 (define %result (begin ,@rest))
                 (set-process-output! %old-output)
                 %result))))
    (cons 'buffer-output
          (lambda rest
            `(let ((%old-output (current-output-port))
                   (%buffer (open-output-string)))
               (set-process-output! %buffer)
               (guard (lambda (%e)
                        (set-process-output! %old-output)
                        (write (get-output-string %buffer))
                        (re-error %e))
                 (define %result (begin ,@rest))
                 (set-process-output! %old-output)
                 (write (get-output-string %buffer))))))
    (cons 's:
          (lambda (stmt . rest)
            `(if *spot-test?*
               (do-s '(,stmt ,@rest) (lambda () ,stmt ,@rest)))))
    (cons 'r:
          (lambda (stmt . rest)
            `(if *spot-test?*
               (do-r '(,stmt ,@rest) (lambda () ,stmt ,@rest)))))
    (cons 't:
          (lambda (stmt . rest)
            `(if *spot-test?*
               (do-t '(,stmt ,@rest) (lambda (_) ,stmt ,@rest)))))
    (cons 'define-class
        (lambda (class-tag super-class make-proto pred-name . class-fields)
          (define class-name (make-symbol "<" class-tag ">"))
          (define (bind-field-accessor access-name field-name)
            `(define ,access-name 
               (make-multimethod 
                 (list ,class-name) 
                 (make-field-accessor ,class-name (quote ,field-name))
                 (or (? ,access-name) refuse-method))))

          (define (bind-field-modifier modif-name field-name)
            `(define ,modif-name 
               (make-multimethod 
                 (list ,class-name #t) 
                 (make-field-modifier ,class-name (quote ,field-name))
                 (or (? ,modif-name) refuse-method))))

          `(begin 
             (define ,class-name  (make-class ',class-tag 
                                              ,super-class 
                                              ',(map-car class-fields)))
             (define (,pred-name %value) (isa? %value ,class-name))
             (define ,(car make-proto) (make-class-constructor 
                                         ',class-name 
                                         ,class-name
                                         ',(cdr make-proto)))
             ,@(map (lambda (field) 
                      (if (> (length field) 1)
                        (bind-field-accessor (cadr field) (car field))
                        '(begin)))
                    class-fields)

             ,@(map (lambda (field) 
                      (if (> (length field) 2)
                        (bind-field-modifier (caddr field) (car field))
                        '(begin)))
                    class-fields))))

    (cons 'define-record-type
          (lambda (record-name make-proto pred-name . record-fields)
            `(define-class ,record-name <record> ,make-proto ,pred-name 
                           ,@record-fields)))
    (cons 'guard
          (lambda (fn . rest)
            (let ((el (make-branch-symbol 'exit)))
              `(asm (mos ,fn)
                    (gar ,el)
                    (mos (begin ,@rest))
                    (rag)
                    ,el))))
    (cons 'case 
      (lambda (expr . branches)
        (let ((tc (make-tc))
              (done (make-branch-symbol 'done))
              (next #f))
          (tc-append! tc `(mos ,expr))
          (for-each (lambda (branch)
                      (when next (tc-append! tc next))
                      (set! next #f)
                      (let ((test (car branch))
                            (body (cdr branch)))
                        (if (eq? test 'else)
                          (begin 
                            (tc-append! tc '(drop))
                            (tc-append! tc `(mos ,@body))
                            (tc-append! tc `(jmp ,done)))
                          (let ((case-branch (make-branch-symbol 'case)))
                            (set! next (make-branch-symbol 'next))
                            (for-each (lambda (value)
                                        (tc-append! tc '(copy)) 
                                        (tc-append! tc `(ldc ,value))
                                        (tc-append! tc '(ldc 2))
                                        (tc-append! tc '(ldg eq?))
                                        (tc-append! tc '(call))
                                        (tc-append! tc `(jt ,case-branch)))
                                      test)
                            (tc-append! tc `(jmp ,next))
                            (tc-append! tc case-branch)
                            (tc-append! tc '(drop))
                            (tc-append! tc `(mos ,@body))
                            (tc-append! tc `(jmp ,done))))))
                    branches)
          (when next
            (tc-append! tc next)
            (tc-append! tc '(drop))
            (tc-append! tc '(ldu)))
          (tc-append! tc done)
          `(asm ,@(tc->list tc)))))
    (cons 'cond (lambda clauses 
                  ;TODO: Should raise an error if there is rest with else.
                  (if (null? clauses) 
                    #f
                    (let ((clause (car clauses))
                          (rest (cdr clauses)))
                      (if (eq? (car clause) 'else)
                        `(begin ,@(cdr clause))
                        `(if ,(car clause)
                           (begin ,@(cdr clause))
                           (cond ,@rest)))))))
    (cons 'when (lambda (test . rest)   `(if ,test (begin ,@rest))))
    (cons 'unless (lambda (test . rest) `(if ,test (begin) (begin ,@rest))))
    (cons 'while (lambda (test . rest)  
                   (let ((enter (make-branch-symbol 'enter))
                         (exit  (make-branch-symbol 'exit)))
                     `(asm (ldc #f)
                           ,enter
                           (mos ,test) 
                           (jf ,exit) 
                           (drop)
                           (mos ,@rest)
                           (jmp ,enter)
                           ,exit))))
    (cons 'until (lambda (test . rest)  
                   (let ((enter (make-branch-symbol 'enter))
                         (exit  (make-branch-symbol 'exit)))
                     `(asm (ldc #f)
                           ,enter
                           (mos ,test) 
                           (jt ,exit) 
                           (drop)
                           (mos ,@rest)
                           (jmp ,enter)
                           ,exit))))
    (cons 'or (lambda (test . rest)  
                (if (null? rest)
                      test
                  (let ((done (make-branch-symbol 'done)))
                    `(asm (mos ,test)
                          (copy)
                          (jt ,done)
                          (drop)
                          (mos (or ,@rest))
                          ,done)))))
    (cons 'and (lambda (test . rest)  
                 (if (null? rest)
                   test
                   (let ((done (make-branch-symbol 'done)))
                     `(asm (mos ,test)
                           (copy)
                           (jf ,done)
                           (drop)
                           (mos (and ,@rest))
                           ,done))))))) 

(define *mosvm-specials*
  (list
    (cons 'quasiquote
      (lambda (block env terms)
        (define temps '())
        (define (add-temp sym)
          (let ((r (make-branch-symbol sym)))
            (set! temps (cons (cons sym r)
                              temps))
            r))
        (define (get-temp sym) (let ((r (assq sym temps)))
                                 (if r (cdr r)
                                   (add-temp sym))))
        (define (inner-qq terms)
          (unless (or (pair? terms) (null? terms))
            (error 'compile 
                   "quasiquote requires a list argument for its template"
                   terms))
          ;Emit a call to make-tc
          (block-append! block '(ldc 0))
          (block-append! block '(ldg make-tc))
          (block-append! block '(call))
          ;For each term:
          (for-each (lambda (term)
                      (cond 
                        ;If the term isn't a pair:
                        ((and (symbol? term) (symbol-starts-with? term 37))
                         (block-append! block (list 'ldc (get-temp term)))
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-append!))
                         (block-append! block '(call)))

                        ((or (null? term) (not (pair? term)))
                         ;Emit an LDC, followed by a call to tc-append!    
                         (block-append! block (list 'ldc term))
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-append!))
                         (block-append! block '(call)))

                        ;Or, if the start of the term is UNQUOTE:
                        ((eq? (car term) 'unquote)
                         ;Compile the unquoted expression, call tc-append!
                         (unless (= (length term) 2)
                           (error 'compile
                                  "unquote requires one argument" term))
                         (compile-expr block (cadr term) env)
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-append!))
                         (block-append! block '(call)))

                        ;Or, if the start of the term is UNQUOTE-SPLICING:
                        ((eq? (car term) 'unquote-splicing)
                         ;Compile the unquoted expression, call tc-splice!
                         (unless (= (length term) 2)
                           (error 'compile 
                                  "unquote-splice requires one argument" 
                                  term))
                         (compile-expr block (cadr term) env)
                         (block-append! block '(ldc 2))
                         (block-append! block '(ldg tc-splice!))
                         (block-append! block '(call)))

                        ;Otherwise:
                        (else
                          ;Begin a new instance of QQ-LIST
                          ;Emit an LDC, followed by a call to tc-append!
                          (inner-qq term)
                          (block-append! block '(ldc 2))
                          (block-append! block '(ldg tc-append!))
                          (block-append! block '(call)))))
                    terms)
          ;Emit a call to tc->list!
          (block-append! block '(ldc 1))
          (block-append! block '(ldg tc->list))
          (block-append! block '(call)))
        (inner-qq terms)))
    (cons 'quote (lambda (block env value) 
                   (block-append! block `(ldc ,value))))
    (cons 'asm (lambda (block env . stmts)
                 (for-each 
                   (lambda (stmt) 
                     (if (and (pair? stmt) (eq? 'mos (car stmt)))
                       (compile-block block (cdr stmt) env)
                       (block-append! block stmt)))
                   stmts)))
    (cons 'begin (lambda (block env . stmts)
                   (compile-block block stmts env)))
    (cons 'if (lambda (block env test t-expr . rest)
                (define f-expr 
                  (case (length rest)
                    ((0) '(begin))
                    ((1) (car rest))
                    (else 
                      (error "if only accepts a test, and two branches."))))
                (let ((done-branch (make-branch-symbol 'done))
                      (false-branch (make-branch-symbol 'false)))
                  (compile-expr block test env)
                  (block-append! block (list 'jf false-branch))
                  (compile-expr block t-expr env)
                  (block-append! block (list 'jmp done-branch))
                  (block-append! block false-branch)
                  (compile-expr block f-expr env)
                  (block-append! block done-branch))))
    (cons 'let (lambda (block env defns . body)
                 (let ((n-env (make-virtual-context env (map car defns))))
                   (for-each 
                     (lambda (x) 
                       (compile-expr block (cadr x) env)
                       (blocq-append! 
                         block (cons 'stb 
                                     (context-symbol-addr n-env (car x)))))
                       defns)
                   (compile-block block body n-env))))
    (cons 'set!  (lambda (block env . expr)
                   (compile-store block expr env)
                   (block-append! block '(ldu))))
    (cons 'lambda (lambda (block env formals . body)
                    (compile-function block
                                      (parse-formals formals)
                                      body
                                      env)))
    (cons '?  (lambda (block env key)
                (let ((addr (context-symbol-addr env key)))
                  (if addr 
                    (block-append! block (cons 'ldb addr))
                    (compile-expr block 
                                  `(get-global (quote ,key)) 
                                  env)))))
    (cons '?? (lambda (block env key)
                (cond 
                  ((is-top-context? env)
                   (compile-expr block `(get-global (quote ,key)) env))
                  ((is-top-context? (context-parent env))
                   (compile-expr block `(get-global (quote ,key)) env))
                  (else
                    (let ((addr (context-symbol-addr env key)))
                      (if addr 
                        (block-append! block (cons 'ldb addr))
                        (compile-expr block 
                                      `(get-global (quote ,key)) 
                                      env)))))))
    ))

(define (make-scheme-program) (make-tc))

(define (make-block scheme-program) 
  (let ((block (cons scheme-program (make-tc))))
    (tc-append! scheme-program block)
    block))  

(define (block-scheme-program block) (car block))

(define (block-append! block stmt) 
  (tc-append! (cdr block) stmt))

(define (block-prepend! block stmt) 
  (tc-prepend! (cdr block) stmt))

(define blocq-append! block-append!)

(define (scheme-program->list scheme-program) 
  (let ((pl (make-tc)))
    (for-each (lambda (block)
                (for-each (lambda (stmt) 
                            (tc-append! pl stmt))
                          (tc->list (cdr block))))
              (tc->list scheme-program))
    (tc->list pl)))

(define (expand-loop expr env)
  (cond
    ((null? expr) expr)
    ((pair? expr) (cons (expand (car expr) env)
                        (expand-loop (cdr expr) env)))
    (else (expand expr env))))

(define (expand expr env)
  (cond ((null? expr) '())
        ((not (pair? expr)) expr)
        ((assq (car expr) *mosvm-specials*) expr)
        (else   
          (set! expr (expand-loop expr env))
          (let ((syn (find-context-rule env (car expr))))
            (if syn (expand (apply syn (cdr expr)) env)
                    expr)))))

(define (compile-exports code env)
  (define tc (make-tc))

  (define (is-export? expr)
    (and (pair? expr)
         (not (null? expr))
         (eq? (car expr) 'export)))

  (define (isnt-export? expr)
    (not (is-export? expr)))

  ;TODO: This needs to be a set.
  (for-each (lambda (x) (tc-splice! tc (cdr x)))
            (filter is-export? code))

  (unless (tc-empty? tc)
    (set-context-exports! env (tc->list tc)))

  (filter isnt-export? code))

(define (compile-defines code env)
  (define (is-define? expr)
    (and (pair? expr)
         (not (null? expr))
         (eq? (car expr) 'define)))

  (define (compile-decl sym env)
    (cond ((and (is-top-context? env)
                (is-exported? sym env)) 
           #f)
          (else 
           (add-context-binding! env sym)
           #t)))
           
  (define (compile-define expr)
    (when (< (length expr) 2)
      (error 'compile 
             "the define form requires a term to define, and a definition" 
             expr))
    (let ((term (cadr expr))
          (body (cdr (cdr expr))))
    
      (if (pair? term)
        (let ((args (cdr term)))
          (set! term (car term))

          (if (and (pair? args) (any pair? (unkink args)))
            ;;;TODO: These should be named-lambda's.
            (set! body `(make-multimethod (list ,@(parse-signature args))
                                          (lambda ,(parse-slots args)
                                            ,@body)
                                          (or (?? ,term) refuse-method)))
            (set! body `(lambda ,args ,@body))))
        (if (= (length body) 1)
          (set! body (car body))
          (error 'compile "variable definitions should be one expression"
                 expr)))

      (compile-decl term env)
      (list 'set! term body)))
    
  (map (lambda (stmt)
         (if (is-define? stmt)
           (compile-define stmt)
           stmt))
       code))

(define (compile-imports code env) 
  (define (is-import? expr) 
    (and (pair? expr)
         (= (length expr) 2)
         (eq? (car expr) 'import)
         (string? (cadr expr))))

  (define (compile-dependency path)
    (define code (read-module path))
    (define exports (list))
    
    (define (compile-imported-export expr)
       (for-each (lambda (item) 
                   (set! exports (cons item exports)))
                 (cdr expr)))
    
    (define (compile-imported-macro expr)
       (define args (cadr expr))
       (define body (cdr (cdr expr)))
       (define name (car args))
       (set! args (cdr args))

       (when (memq name exports)
         (add-context-rule! env (make-procedure args body))))

    (for-each compile-imported-export
              (filter is-export? data))

    (for-each compile-imported-macro 
              (filter is-macro? data)))

  (define (compile-import expr) 
    (define id (cadr expr))
    (compile-dependency (module-dependencies id)))
    
  (for-each compile-import (filter is-import? code)))

(define (compile-macros code env)
  (define (is-macro? expr)
    (and (pair? expr)
      (not (null? expr))
      (eq? (car expr) 'define-macro)))
 
  (define (isnt-macro? expr)
    (not (is-macro? expr)))

  (define (compile-macro expr)
    (when (< (length expr) 3)
      (error 'compile
             "the define-macro form requires a form and a body"
             expr))
    (let ((args (cadr expr))
          (body (cdr (cdr expr))))
      (unless (pair? args)
        (error 'compile
               "the define-macro form requires a list for its form"
               expr))
      (let ((name (car args)))
        (set! args (cdr args))
        (add-context-rule! env name (make-procedure args body))
        (if (and (is-top-context? env)
                 (is-exported? name env))
          `(set-macro! ,name (lambda ,args ,@body))
          '(begin)))))

  (map (lambda (expr)
         (if (is-macro? expr) 
           (compile-macro expr) 
           expr))
       code))

(define (compile code)
  ;; I loathe nested lets, but Scheme's inner defines are let-like,
  ;; and MOSVM doesn't do letrec.
  (let ((program (make-scheme-program)))
    (let ((base-block (make-block program))
          (top-context (make-top-context)))
      (set! code (compile-exports code top-context))
      (compile-imports code top-context)
      (compile-block base-block code top-context)
      (block-prepend! base-block 
                      (list 'usen 0 (context-slot-count top-context)))
      (block-append! base-block '(retn))
      (scheme-program->list program))))

(define (compile-block block code env)
  ;; This will produce an extra ldu/drop at the beginning of any non-null
  ;; block, but the optimizer will detect and remove it.
  (block-append! block '(ldu))
  (set! code (compile-macros code env))
  (set! code (compile-defines code env))
  (until (null? code)
    (block-append! block '(drop))
    (compile-expr block (car code) env)
    (set! code (cdr code))))

(define (compile-expr block expr env)
  (cond ((null? expr)    (compile-null block env))
        ((list? expr)    (compile-form block expr env))
        ((integer? expr) (compile-integer block expr env))
        ((string? expr)  (compile-string block expr env))
        ((symbol? expr)  (compile-load block expr env))
        ((eq? expr #f)   (compile-false block env))
        ((eq? expr #t)   (compile-true block env))
        (else (error 'compile "unrecognized expression" expr))))

(define (compile-null block env) (compile-constant block '() env))
(define (compile-true block env) (compile-constant block #t env))
(define (compile-false block env) (compile-constant block #f env))
(define (compile-string block expr env)   (compile-constant block expr env))
(define (compile-integer block expr env)  (compile-constant block expr env))
(define (compile-constant block expr env) (block-append! block (list 'ldc expr)))

(define (compile-form block expr env)
  (set! expr (expand expr env))
  (if (pair? expr)
    (let ((rule (assq (car expr) *mosvm-specials*)))
      (if rule 
        (apply (cdr rule) block env (cdr expr))
        (compile-call block env expr)))
    (compile-expr block expr env)))

(define-record-type <formals>
                    (make-formals fluidf signature slots)
                    formals?
                    (fluidf fluid-formals?)
                    (signature formal-signature)
                    (slots formal-slots))

(define (method-formals? formals) (formal-signature formals))

(define (parse-signature args)
  (if (any pair? (unkink args))
    (map (lambda (i) 
           (if (pair? i) 
             (car i)
             #t))
         args)
    #f))

(define (parse-slots args)
  (map (lambda (i)
         (if (pair? i)
           (cadr i)
           i))
       args))

(define (parse-formals formals)
  (cond 
    ((symbol? formals)     (make-formals #t #f (list formals)))
    ((null? formals)       (make-formals #f #f '()))
    ((not (pair? formals)) (error 'compile "indecipherable formals" formals))
    ((symbol? (cdr (last-pair formals)))
     (set! formals (unkink formals))
     (make-formals #t (parse-signature formals) (parse-slots formals)))
    (else (make-formals #f (parse-signature formals) (parse-slots formals)))))

(define (compile-function outer formals body env)
  (set! env (make-actual-context env (formal-slots formals)))
  (let ((label (make-branch-symbol 'lambda))
        (inner (make-block (block-scheme-program outer)))
        (args  (formal-slots formals)))
    
    (compile-block inner body env)
    (block-append! inner '(retn))
    (block-prepend! inner (if (fluid-formals? formals)
                            (list 'usea 
                                  (- (length args) 1) 
                                  (context-slot-count env))
                            (list 'usen 
                                  (length args) 
                                  (context-slot-count env))))
    (block-prepend! inner label)

    (block-append! outer (list 'ldf label))))

(define (compile-load block sym env) 
  ;TODO Test for is-imported?
  (let ((addr (context-symbol-addr env sym)))
    (block-append! block (if addr (cons 'ldb addr)
                                  (list 'ldg sym)))))

(define (compile-store block expr env) 
  ;TODO Test for is-imported?
  (let ((sym (car expr))
        (val (cadr expr)))
    (compile-expr block val env)
    (let ((addr (context-symbol-addr env sym)))
      (block-append! block (if addr (cons 'stb addr)
                                    (list 'stg sym))))))

(define (fix-mixed-formals formals)
  (let ((tc (make-tc)))
    (while (pair? formals)
      (tc-append! tc (car formals))
      (set! formals (cdr formals)))
    (tc-append! tc formals)
    (tc->list tc)))

(define (compile-mixed-lambda block formals body env)
  (set! formals (fix-mixed-formals formals))
  (set! env (make-actual-context env formals))
  (compile-block block body env)
  (block-prepend! block (list 'usea 
                              (- (length formals) 1)
                              (context-slot-count env))))

(define (compile-call block env expr) 
  (compile-args block (cdr expr) env)
  (compile-expr block (car expr) env)
  (block-append! block '(call)))

(define (compile-args block args env)
  (for-each (lambda (arg) 
              (compile-expr block arg env))
            args)
  (block-append! block (list 'ldc (length args))))

