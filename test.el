;; This buffer is for text that is not saved, and for Lisp evaluation.
;; To create a file, visit it with C-x C-f and enter text in its buffer.

(add-to-list 'load-path "~/work/tramp-libssh/build")
(require 'emacs-libssh)

(defun test-emacs-libssh-get-session ()
  (interactive)
  (emacs-libssh-get-session nil "dev")
  )


