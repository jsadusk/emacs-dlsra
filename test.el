;; This buffer is for text that is not saved, and for Lisp evaluation.
;; To create a file, visit it with C-x C-f and enter text in its buffer.

(add-to-list 'load-path "~/work/tramp-libssh/build")
(require 'emacs-libssh)

(defun test-emacs-libssh-get-session ()
  (interactive)
  (message "get session")
  (setq libssh-session (emacs-libssh-get-ssh-session nil "dev"))
  (message "get sftp")
  (setq libssh-sftp (emacs-libssh-get-sftp-session libssh-session))
  )


(defun test-emacs-libssh-insert ()
  (interactive)
  (message "sftp insert")
  (emacs-libssh-sftp-insert libssh-session libssh-sftp "/home/jsadusk/.bashrc" -1 -1)
  )

(defun test-emacs-libssh-insert-region ()
  (interactive)
  (message "sftp insert 20 - 500")
  (emacs-libssh-sftp-insert libssh-session libssh-sftp "/home/jsadusk/.bashrc" 23 590)
  )
