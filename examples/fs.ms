(let ((f (file-open "lib/core.ms" "r")))
  (show "core file size is ")
  (show (file-seek f -1))
  (newline)
  (file-close f))

;;; MOSVM2
;;; MOSVM2
