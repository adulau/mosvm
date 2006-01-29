(define (kabuki-filter lines)
  (define in (make-tc lines))
  (define out (make-tc))

  (define line #f)

  (define (next) (set! line (tc-next! in)))
  (define (keep) 
    (show "    Keeping:")(show line)(newline)
    (tc-append! out line))
  (define (drop)
    (show "    Dropping:")(show line)(newline))

  (until (tc-empty? in)
    (next)    
    (cond
      ;;; All IC lines must be kept, and start with " --"
      ((string-begins-with line " --") 
       (keep))

      ;;; All OOC lines must be dropped, and start with " ::"
      ((string-begins-with line " ::") 
       (drop))

      ;;; All remaining lines must be Systems which start with
      ;;; **, or are command feedback.
      ((not (string-begins-with line " **")) 
       (drop))

      ;;; All system arrival commands should be kept.
      ((string-find line "has arrived in")
       (keep))

      ;;; All other system lines shall be dropped.
      (else (drop))))

  (tc->list out))

(define (kabuki-filter-file src-path dst-path)
  (show "  Opening ")(show src-path)(show "..")(newline)
  (define src-file (open-input-file src-path))

  (show "  Reading ")(show src-path)(show "..")(newline)
  (define src-lines (read-lines src-file))
  (close src-file)

  (show "  Filtering log..")(newline)
  (define dst-lines (kabuki-filter src-lines))

  (show "  Opening ")(show dst-path)(show "..")(newline)
  (define dst-file (open-output-file dst-path))

  (show "  Writing log to ")(show dst-path)(show "..")(newline)
  (write (apply string-join *line-sep* dst-lines)
         dst-file)
  (close dst-file)

  (show "Done."))

(define (usage)
  (show "kabuki-filter <src-file> <dst-file>")
  (newline)
  (show "filters a Kabuki session log to remove OOC and system cruft that is not")
  (newline)
  (show "worth sharing in a public log.")
  (newline)
  (newline)
  (show "Do not use kabuki-filter on the master copy of your log file."))

(case (argc)
  ((3) (kabuki-filter-file (argv 1) (argv 2)))
  (else (usage)))

