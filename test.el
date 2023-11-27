;; This buffer is for text that is not saved, and for Lisp evaluation.
;; To create a file, visit it with C-x C-f and enter text in its buffer.

(add-to-list 'load-path "~/work/emacs-dlsra/build")
(require 'dlsra)

(defun dlsra-get-file-to-buffer (path)
  (interactive "sPath:")
  (dlsra-get-file-to-buffer-c path (current-buffer))
  )


(find-file)
(tramp-find-host)
