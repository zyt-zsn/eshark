(require'pcap-mode)

;; (pcap-mode-capture-file "d:/Temp/xl.pcapng" (progn (scratch-buffer) (current-buffer)))
;; (pcap-mode-capture-file "d:/Temp/xl.pcapng" (find-file "d:/Temp/xl.pcapng"))
;; (shell-command
;;  "c:/Windows/system32/tshark.exe -i \"\\Device\\NPF_{D82798C5-0AD2-4EFE-9112-3FC3A5E41F66}\" -w \"d:/Temp/xl.pcapng\" -a duration:10 -s 65535 "
;;  (progn (scratch-buffer) (current-buffer)))
;; (shell-command "c:/Windows/system32/tshark.exe -r \"d:/Temp/xl.pcapng\" " (progn (scratch-buffer) (current-buffer)))

;; (shell-command "dumpcap -q -a duration:10 -s 65535 -i 6 -w - | tshark -r -" (progn (scratch-buffer) (current-buffer)))
;; (shell-command "dumpcap -q -a duration:10 -s 65535 -i 6 -w - | tshark -r -&" (progn (scratch-buffer) (current-buffer)))
;; (shell-command "dumpcap -q -i \\Device\\NPF_{D82798C5-0AD2-4EFE-9112-3FC3A5E41F66} -w - | tshark -r -&" (get-buffer-create "net sniffer"))
;; (shell-command "dumpcap -q -i \\Device\\NPF_{D82798C5-0AD2-4EFE-9112-3FC3A5E41F66} -w -|tee zytxl.pcapng | tshark -r -&"  (progn (scratch-buffer) (current-buffer)))

;; ref Chatgpt: how to get process object of shell-command in elisp
(defun zyt/run-shell-command-and-capture-process (command buffer-or-name)
  "Run a shell command and return the process object."
  (let ((process-name "zyt/shell-process"))
	(start-process process-name buffer-or-name "sh" "-c" command)))
;; (setq my-process (zyt/run-shell-command-and-capture-process "ls -l | grep exe" "*Shell Command Output*"))
;; (setq my-process (zyt/run-shell-command-and-capture-process "dumpcap -q -i \\\\Device\\\\NPF_{D82798C5-0AD2-4EFE-9112-3FC3A5E41F66} -w -|tee d:/temp/zytxlzsn.pcapng | tshark -r -&" "*Shell Command Output*"))

(defcustom tshark-capture-temp-file "d:/temp/zytxlzsn.pcapng" "Temporary file when capture network packets")

(defcustom zyt/real-time-sniffer-buffer-name "zyt net sniffer" "Sniffer buffer of network packets")
(defvar zyt/real-time-sniffing nil)
(defvar zyt/real-time-sniffer-process nil)
(defvar zyt/real-time-sniffer-detail-process nil)
(defconst zyt/real-time-sniffer-detail-buffer-name "*Packet detail info*")
(defun zyt/real-time-sniffer-stop()
  (interactive)
  (if zyt/real-time-sniffing
	  (progn
		(if (process-live-p zyt/real-time-sniffer-process)
			(kill-process zyt/real-time-sniffer-process)
		  )
		(sleep-for 0 1000)
		(delete-file tshark-capture-temp-file)
		(setq zyt/real-time-sniffing nil)
		)
	)
  )

;;;###autoload
(defun zyt/real-time-sniffer-toggle()
  (interactive)
  (if zyt/real-time-sniffing
	  (progn
		(if (process-live-p zyt/real-time-sniffer-process)
			(kill-process zyt/real-time-sniffer-process)
		  )
		(kill-buffer (find-file-noselect tshark-capture-temp-file t t))
		(setq zyt/real-time-sniffing nil)
		)
	(let ((cle current-language-environment))
	  (condition-case err
		  (progn
			(with-current-buffer (get-buffer-create zyt/real-time-sniffer-buffer-name)
			  (setf buffer-file-name tshark-capture-temp-file)
			  (progn
				(erase-buffer)
				(setq-local zyt/real-time-sniff-minor-mode t)
				(setq zyt/real-time-sniffer-process
					  (make-process
					   :name "Sniffer process"
					   :buffer zyt/real-time-sniffer-buffer-name
					   :coding 'utf-8
					   :command
					   (list "sh" "-c" (format "tshark -i \\\\Device\\\\NPF_{D5FFB044-EADB-42ED-9A27-DB408505F1EC} -l -P -w %s" tshark-capture-temp-file))
					   ;; :filter #'zyt/real-time-sniffer-filter
					   )
					  )
				(zyt/sniffer-reset-detail-buffer)
				)
			  )
			(setq zyt/real-time-sniffing t)
			(switch-to-buffer zyt/real-time-sniffer-buffer-name)
			(setq-local kill-buffer-hook '(t))
			(add-to-list 'kill-buffer-hook #'zyt/real-time-sniffer-stop)
			;; Add sleep guarding time due to the asynchronous mode of command:`&
			(sleep-for 3))
		(t (set-language-environment cle))
		)
	  )
	)
  )
(defun zyt/sniffer-reset-detail-buffer()
  (with-current-buffer (get-buffer-create zyt/real-time-sniffer-detail-buffer-name)
	(erase-buffer)
	)
  )
(defvar zyt/sniffer-target-frame-number nil)
(defconst zyt/real-time-sniffer--buffer-frame-number-regexp "^ +\\([[:digit:]]+\\) +")
(defvar-local zyt/sniffer-auto-switch-to-detail-buffer nil)
(defun zyt/sniffer-view-pkt-content(&optional switch-to-detail-buffer target-frame-number)
  "Pop out the detail info of frame on cursor; If `SWITCH-TO-DETAIL-BUFFER` is not nil, jump to the detail info buffer "
  (interactive)
  (setq zyt/sniffer-auto-switch-to-detail-buffer switch-to-detail-buffer)
  (if-let (
		   (cur-buffer (current-buffer))
		   (frame-number
			(or target-frame-number
				(save-excursion
				  (if-let (
						   (line (thing-at-point 'line))
						   (match (progn
									(string-match zyt/real-time-sniffer--buffer-frame-number-regexp line)
									(match-string 1 line)))
						   )
					  (string-to-number match)
					)
				  ))
			)
		   (cle current-language-environment)
		   )
	  (with-current-buffer (get-buffer-create zyt/real-time-sniffer-detail-buffer-name)
		(unless
			(or  (if-let ((frame
						   (zyt/real-time-sniffer-narrow-frame frame-number)))
					 (progn
					   (pop-to-buffer zyt/real-time-sniffer-detail-buffer-name)
					   (zyt/sniffer-detail-minor-mode)
					   (goto-char 1)
					   (unless zyt/sniffer-auto-switch-to-detail-buffer
						 (pop-to-buffer cur-buffer)
						 )
					   frame)
				   )
				 (process-live-p zyt/real-time-sniffer-detail-process))
		  (setq buffer-read-only nil)
		  (erase-buffer)
		  (setq zyt/sniffer-target-frame-number frame-number)
		  (with-current-buffer cur-buffer
			(pcap-mode-view-pkt-contents)
			(zyt/sniffer-detail-minor-mode)
			)
		  (when (process-live-p zyt/real-time-sniffer-detail-process)
			(kill-process zyt/real-time-sniffer-detail-process)
			(while (process-live-p zyt/real-time-sniffer-detail-process))
			)
		  (message "Start hexdumping ... ")
		  (setq zyt/real-time-sniffer-detail-process (make-process
													  :name "net packet detail process"
													  :buffer (current-buffer)
													  ;; :command (list "sh" "-c" (format "tshark -r %s -Y \"frame.number==%s\" -V --hexdump delimit" tshark-capture-temp-file frame-number))
													  :command (list "sh" "-c" (format "tshark -r %s -V --hexdump delimit" tshark-capture-temp-file frame-number))
													  :coding 'gb18030-dos
													  :stdrrr (get-buffer-create "*Packet detail err*")
													  :sentinel (lambda(process evt-string)
																  (when (string= evt-string "finished\n")
																	(setq buffer-read-only t)
																	(let ((cur-buffer (current-buffer)))
																	  (pop-to-buffer zyt/real-time-sniffer-detail-buffer-name)
																	  (zyt/real-time-sniffer-narrow-frame zyt/sniffer-target-frame-number)
																	  (zyt/sniffer-detail-minor-mode)
																	  (goto-char 1)
																	  (unless zyt/sniffer-auto-switch-to-detail-buffer
																		(pop-to-buffer cur-buffer)
																		)
																	  )
																	))
													  ))
		  )
		)
	)
  )
(defun zyt/sniffer--detail-mode-next-frame()
  (interactive)
  (let (
		(cur-frame-number (zyt/real-time-sniffer-nearby-frame-number))
		)
	(zyt/sniffer-view-pkt-content nil (1+ cur-frame-number))
	(when (and zyt/sniffer--follow-mode (get-buffer-window zyt/real-time-sniffer-buffer-name))
	  (let ((cur-buffer (current-buffer)))
		(with-current-buffer zyt/real-time-sniffer-buffer-name
		  (next-line)
		  )
		;; (pop-to-buffer cur-buffer)
		)
	  )
	)
  )
(defun zyt/sniffer--detail-mode-previous-frame()
  (interactive)
  (let (
		(cur-frame-number (zyt/real-time-sniffer-nearby-frame-number))
		)
	(if (> cur-frame-number 1)
		(zyt/sniffer-view-pkt-content nil (1- cur-frame-number)))
	)
  )

(defvar zyt/real-time-sniff-detail-mode-map
  (let ((map (make-sparse-keymap)))
	(keymap-set map "q" #'zyt/sniffer-view-pkt-content-quit)
	(keymap-set map "<tab>" #'outline-cycle)
	(keymap-set map "C-n" #'zyt/sniffer--detail-mode-next-frame)
	(keymap-set map "C-p" #'zyt/sniffer--detail-mode-previous-frame)
	(keymap-set map "<backtab>" #'outline-cycle-buffer)
	map
	)
  )
(define-minor-mode zyt/sniffer-detail-minor-mode
  "Zyt/sniffer detail content minor mode"
  :lighter " N&D"
  :keymap zyt/real-time-sniff-detail-mode-map
  (progn
	(outline-minor-mode -1) ;;Reset to normal-mode to reset `underlying face`to avoid resizing :height/:wight relatively to current value each time when entering zyt/sniffer-detail-minor-mode.
	(setq-local outline-regexp "\\(^\\w\\)\\|\\(^ \\{4,64\\}\\)")
	(face-spec-set 'outline-1 '((t (:extend t :foreground "yellow" :weight bold :height 1.2))))
	(face-spec-set 'outline-4 '((t (:extend t :foreground "steel blue" :weight bold :height 1))))
	(face-spec-set 'outline-8 '((t (:extend t :foreground "#e6eeff" :slant italic :weight thin :height 0.8))))
	(setq-local outline-minor-mode-highlight  t)
	(setq buffer-read-only t)
	(outline-minor-mode)
	(outline-hide-sublevels 1)
	)  
  )


(advice-add
 'zyt/sniffer-view-pkt-content
 :around #'advice-coding-wrapper
 )
;; (advice-remove 'zyt/sniffer-view-pkt-content #'advice-coding-wrapper)
(defun zyt/sniffer-view-pkt-content-quit()
  (interactive)
  (kill-buffer)
  )
(defvar zyt/sniffer--follow-mode nil)

(defvar zyt-sniffer--vier-pkt-details-timer nil)
(defun zyt/real-time-sniffer-line-move-wrapper(orig &rest args)
  "为 zyt/real-time-sniffer 的follow模式特殊处理"
  (prog1
	  (apply orig args)
	(when (and zyt/real-time-sniff-minor-mode zyt/sniffer--follow-mode)
	  (if zyt-sniffer--vier-pkt-details-timer
		  (cancel-timer zyt-sniffer--vier-pkt-details-timer))
	  (setq zyt-sniffer--vier-pkt-details-timer (run-at-time 0.2 nil
															 (lambda()
															   (let ((cur-buffer (current-buffer)))
																 (zyt/sniffer-view-pkt-content nil nil)
																 (pop-to-buffer cur-buffer)
																 ))
															 ))
	  )
	)
  )
(advice-add
 'line-move
 :around
 'zyt/real-time-sniffer-line-move-wrapper
 )
(defvar zyt/real-time-sniff-mode-map
  (let ((map (make-sparse-keymap)))
	(define-key map (kbd "<return>")
				(lambda()
				  "Show details of selected packet"
				  (interactive)
				  (zyt/sniffer-view-pkt-content 'switch-to-detail-buffer)))
	(define-key map (kbd "C-c C-f")
				(lambda()
				  "Toggle zyt/sniffer follow mode"
				  (interactive)
				  (setq zyt/sniffer--follow-mode (not zyt/sniffer--follow-mode))
				  )
				)
	map
	)
  )

(define-minor-mode zyt/real-time-sniff-minor-mode
  "Sniff network packets in real time"
  :init-value nil
  :lighter "Sniff"
  :keymap zyt/real-time-sniff-mode-map
  (setq zyt/sniffer--follow-mode t) 
  (setq buffer-read-only t)
  )

;; tshark -q -r zytxl.pcapng -z "dests,tree,tcp.port==80"


;; (setq eshell-buffer-maximum-lines 10)
;; dumpcap -q -i 6 -w - | tshark -r -
;; tshark -q -i 6  -w - | tshark -r -



;; (shell-command
;;  "c:/Wireshark/tshark.exe -r \"d:/Temp/filtertest.pcapng\" frame contains \\\"ytzhang\\\""
;;  (scratch-buffer)
;;  )

;; (shell-quote-argument  "-r d:/Temp/filtertest.pcapng frame contains \"ytzhang\"" )

(defconst frame-number-regexp "Frame \\([[:digit:]]+\\):")
(defun zyt/real-time-sniffer-nearby-frame-number()
  (let ((cnt 1)
		(backward t)
		frame-number)
	(while-let (
				(line
				 (if (thing-at-point 'line)
					 (substring-no-properties
					  (thing-at-point 'line)
					  ))
				 )
				(not-quit
				 (progn
				   (setq frame-number
						 (progn
						   (string-match frame-number-regexp line)
						   (match-string 1 line)))
				   (and 
					(or (> (point-max) (point)) backward)
					(not (s-starts-with? "Frame" line)))
				   )
				 )
				)
	  (forward-line (if backward -1 1))
	  (if (= (point-min) (point))
		  (setq backward nil))
	  )
	(if frame-number (string-to-number frame-number))
	)
  )
(defun zyt/real-time-sniffer-find-frame(frame-number)
  (let (found)
	(save-excursion
	  (let ((current-frame-number
			 (zyt/real-time-sniffer-nearby-frame-number))
			(target-frame-number-regexp
			 (format "Frame %d:" frame-number))
			)
		(cond
		 ((not current-frame-number) nil)
		 (
		  (= frame-number current-frame-number)
		  (setq found (progn (beginning-of-line)(point)))
		  )
		 ((< frame-number current-frame-number)
		  (if
			  (re-search-backward target-frame-number-regexp nil t nil)
			  (setq found (progn (beginning-of-line)(point)))
			)
		  )
		 ((> frame-number current-frame-number)
		  (if
			  (re-search-forward target-frame-number-regexp nil t nil)
			  (setq found (progn (beginning-of-line)(point)))
			)
		  )
		 )
		)
	  )
	(if found (goto-char found)))
  )
(defun zyt/real-time-sniffer-narrow-frame (frame-number)
  "Find target frame indexed by frame-number, narrow region and return the start point; Return nil if not found"
  (let* (
		 (cur-start (point-min))
		 (cur-end (point-max))
		 (cur-point (point))
		 (nop   (widen))
		 (start (zyt/real-time-sniffer-find-frame frame-number))
		 (end (zyt/real-time-sniffer-find-frame (1+ frame-number)))
		 )
	(if start
		(narrow-to-region start (or end (point-max)))
	  (narrow-to-region cur-start cur-end)
	  (goto-char cur-point)
	  )
	start
	)
  )
(provide 'real-time-sniffer)
