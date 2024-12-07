;;; -*- lexical-binding: t -*-
(require 'pcap-mode)
(require 'dash)
(require 'parse-pdml)
(require 'pcase)
(require 'w3m)
(require 's)
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
(defun set-filter(symbol value)
  (let* ((orig-value
		  (symbol-value symbol)
		  ))
	(condition-case var
		(progn
		  (set-default symbol value)
		  (when (buffer-live-p (get-buffer eshark-buffer-name))
			(with-current-buffer eshark-buffer-name
			  (pcap-mode-set-tshark-filter value)
			  ))
		  )
	  ((error) (set-default symbol orig-value))
	  )
	)
  )
(defcustom eshark-display-filter ""
  "Display filter"
  :initialize #'custom-initialize-default
  :set
  #'set-filter
  )

(defcustom eshark-buffer-name "zyt net sniffer" "Sniffer buffer of network packets")
(defvar zyt/real-time-sniffing nil)
(defvar eshark-process nil)
(defvar eshark-detail-process nil)
(defconst eshark-detail-buffer-name "*Packet detail info*")
(defconst eshark-packet-pdml-buffer-name "*Packet pdml*")
(defconst eshark-frame-hex-buffer-name "*Frame hex*")
(defconst eshark-reassembled-hex-buffer-name "*Reassambled hex*")
(defvar eshark-hex-buffer nil)
(defvar eshark-detail-buffer nil)

(defun eshark-stop()
  (interactive)
  (if zyt/real-time-sniffing
	  (progn
		(if (process-live-p eshark-process)
			(kill-process eshark-process)
		  )
		;; (sleep-for 0 1000)
		;; (delete-file tshark-capture-temp-file)
		(setq zyt/real-time-sniffing nil)
		)
	)
  )

(defun eshark-select-intface()
  (let* (
		 (intfs-output
		  (with-temp-buffer
			(let ((coding-system-for-read 'utf-8))
			  (shell-command "tshark -D" (current-buffer))
			)
			(buffer-substring-no-properties (point-min) (point-max))
			)
		  )
		 (option-list
		  (--keep
		   (progn
			 (string-match "[[:digit:]]+\.\s\\(.*\\)\s(\\(.*\\))" it)
			 (cons (match-string 2 it) (match-string 1 it))
			 )
		   (split-string intfs-output "\n" 'omit-null)
		   )
		  )
		 )
	(regexp-quote
	 (alist-get
	  (completing-read
	   "Interface to capture: "
	   option-list
	   (lambda(arg)
		 t
		 )
	   nil
	   nil
	   t
	   )
	  option-list
	  nil
	  nil
	  'string=
	  )
	 )
	)
  )
;;;###autoload
(defun eshark-toggle()
  (interactive)
  (if zyt/real-time-sniffing
	  (eshark-stop)
	(let ((cle current-language-environment))
	  (condition-case err
		  (progn
			(with-current-buffer (get-buffer-create eshark-buffer-name)
			  (setq buffer-read-only nil)
			  (setf buffer-file-name tshark-capture-temp-file)
			  (progn
				(if pdml-ht (clrhash pdml-ht))
				(setq cashed-largest-pdml-number 0)
				(erase-buffer)
				(basic-save-buffer)
				;; (setq-local zyt/real-time-sniff-minor-mode t)
				(pcap-mode)
				(zyt/real-time-sniff-minor-mode)
				(setq eshark-process
					  (make-process
					   :name "Sniffer process"
					   :buffer eshark-buffer-name
					   :coding 'utf-8
					   :command
					   (list "sh" "-c" (format "tshark -i %s -l -P -w %s" (eshark-select-intface) tshark-capture-temp-file))
					   ;; (list "sh" "-c" (format "tshark -i \\\\Device\\\\NPF_{D359831E-00E8-4523-8291-BDC9E119EF8F} -l -P -w %s" tshark-capture-temp-file))
					   ;; :filter #'eshark-filter
					   )
					  )
				(eshark-reset-detail-buffer)
				(eshark--retrive-pdml-bg)
				)
			  )
			(setq zyt/real-time-sniffing t)
			(switch-to-buffer eshark-buffer-name)
			(setq-local kill-buffer-hook '(t))
			(add-to-list 'kill-buffer-hook #'eshark-stop)
			;; Add sleep guarding time due to the asynchronous mode of command:`&
			(sleep-for 3))
		(t (set-language-environment cle))
		)
	  )
	)
  )
(defun eshark-reset-detail-buffer()
  (with-current-buffer (get-buffer-create eshark-detail-buffer-name)
	(setq buffer-read-only nil)
	(erase-buffer)
	(setq buffer-read-only t)
	)
  )
(defvar eshark-target-frame-number nil)
(defconst eshark--buffer-frame-number-regexp "^ *\\([[:digit:]]+\\) [[:digit:]]\\{2\\}:[[:digit:]]\\{2\\}:[[:digit:]]\\{2\\}\.[[:digit:]]\\{6\\}")
(defvar-local eshark-auto-switch-to-detail-buffer nil)
(defvar sniffer-view-detail-timer-delay nil)
(defvar sniffer-view-hex-timer-delay 0.8)
(defcustom eshark-max-extract-pdml-cnt 50 "Max pdml cnt per extract action")
(defvar pdml-ht (make-hash-table :test 'equal))
(defvar cashed-largest-pdml-number 0)
(defvar pending-request-pdml-number nil)
(defun eshark-get-frame-hole(frame-number)
  (let (
		(s-num frame-number)
		(e-num frame-number)
		)
	(while
		(and
		 (> s-num 0)
		 (< (- frame-number s-num) eshark-max-extract-pdml-cnt)
		 (null (gethash s-num pdml-ht))
		 )
	  (cl-decf s-num)
	  )
	(cl-incf s-num)
	(while
		(and
		 (< e-num (+ s-num eshark-max-extract-pdml-cnt))
		 (null (gethash s-num pdml-ht))
		 )
	  (cl-incf e-num)
	  )
	(cl-decf e-num)
	(if (<= s-num e-num)
		(cons s-num e-num)
	  )
	)
  )
(defun eshark-get-pdml(frame-number &optional pcap-file)
  (or pcap-file (setq pcap-file tshark-capture-temp-file))
  (or pdml-ht (setq pdml-ht (make-hash-table :test 'equal)))
  (or (gethash frame-number pdml-ht)
	  ;; (puthash
	  ;;  frame-number
	  ;;  (car (eshark--get-pdml-list frame-number frame-number
	  ;; 									pcap-file))
	  ;;  pdml-ht
	  ;;  )
	  )
  )
(defun eshark--get-pdml-list(start-frame-number end-frame-number pcap-file)
  (with-temp-buffer
  ;; (with-current-buffer (current-buffer)
	(let (
		  (coding-system-for-read 'chinese-gb18030-dos)
		  (coding-system-for-write 'utf-8)
		  )
	  (shell-command
	   (concat "tshark.exe -T pdml -r " pcap-file " -Y \"frame.number>="
			   (int-to-string start-frame-number)
			   " and frame.number<="
			   (int-to-string end-frame-number)
			   "\"")
	   (current-buffer)
	   )
	  (dom-search
	   ;; (libxml-parse-html-region)
	   (libxml-parse-xml-region)
	   (lambda(node)
		 (string= "packet" (dom-tag node))
		 )
	   )
	  )
	)
  )
(defun eshark--retrive-pdml-bg(&optional frame-number update-detail-buffer-request)
  (or frame-number (setq frame-number cashed-largest-pdml-number))
  (unless (process-live-p eshark-detail-process)
	(message "cashed-largest-pdml-number %d:" cashed-largest-pdml-number)
	(when-let ((frame-hole (eshark-get-frame-hole frame-number)))
	  (setq buffer-read-only nil)
	  (with-current-buffer (get-buffer-create " pdml-tmp-buffer")
		;; (with-temp-buffer
		(erase-buffer)
		(let ((inhibit-message t))
		  (message "Start hexdumping %d <--> %d ..." (car frame-hole) (cdr frame-hole))
		  )
		(setq
		 eshark-detail-process
		 (make-process
		  :name "net packet detail process"
		  :buffer (current-buffer)
		  :command (list "sh" "-c" (format "tshark -T pdml -r %s -Y \"frame.number\>=%d and frame.number\<=%d\"" tshark-capture-temp-file (car frame-hole) (cdr frame-hole)))
		  :coding (cons 'utf-8 'chinese-gb18030-dos)
		  :stdrrr (get-buffer-create "*Packet detail err*")
		  :sentinel
		  (lambda(process evt-string)
			(when (string= evt-string "finished\n")
			  (let ((inhibit-message t))
				(message "Hexdumping finished")
				(message "cashed-largest-pdml-number %d" cashed-largest-pdml-number)
				)
			  ;; (with-current-buffer " pdml-tmp-buffer"
			  (with-current-buffer (process-buffer process)
				(let* (
					   (packet-list
						;; [[**  (bookmark--jump-via "("pdml file demo" (filename . "d:/temp/sh-xxxxxx.xml") (front-context-string . "<?xml version=\"1") (rear-context-string) (position . 1) (last-modified 26443 53671 294757 0) (defaults "sh-xxxxxx.xml"))" 'switch-to-buffer-other-window)  **]]
						(dom-search
						 (libxml-parse-html-region)
						 (lambda(node) (string= "packet" (dom-tag node)))
						 ))
					   )
				  (let ((inhibit-message t))
					(message "frame hole<%d-%d>" (car frame-hole) (+ (car frame-hole) (length packet-list)))
					)
				  (if (= (1+ cashed-largest-pdml-number) (car frame-hole))
					  (setq cashed-largest-pdml-number (+ (car frame-hole) (length packet-list) -1)))
				  (let ((inhibit-message t))
					(message "after extraction: cashed-largest-pdml-number %d" cashed-largest-pdml-number)
					)
				  (if (and eshark-target-frame-number
						   (<= (car frame-hole) eshark-target-frame-number (cdr frame-hole)))
					  ;; 更新最新请求
					  (setq frame-number eshark-target-frame-number))
				  (--map-indexed
				   (let ((proto-list (dom-children it)))
					 (puthash (+ (car frame-hole) it-index) proto-list pdml-ht)
					 (when
						 (and update-detail-buffer-request (= frame-number (+ it-index (car frame-hole))))
					   (eshark-view-pkt-content 'switch-to-detail-buffer frame-number) 
					   ;; (with-current-buffer eshark-packet-pdml-buffer-name
					   ;; 	 (setq buffer-read-only nil)
					   ;; 	 (erase-buffer)
					   ;; 	 (--map
					   ;; 	  (insert (assemble-proto it))
					   ;; 	  proto-list)
					   ;; 	 (setq buffer-read-only t)
					   ;; 	 )
					   )
					 )
				   packet-list
				   )
				  (when(
						and eshark-target-frame-number
						(= eshark-target-frame-number frame-number)
						)
					(setq eshark-target-frame-number nil))
				  (when packet-list
					(if eshark-target-frame-number
						(prog1
							(run-at-time 0.1 nil (lambda()
												 (eshark--retrive-pdml-bg eshark-target-frame-number 'update-detail-buffer-request)))
						  (message "start timer lambda")
						  )
					  (message "start timer eshark--retrive-pdml-bg")
					  (run-at-time 0.1 nil #'eshark--retrive-pdml-bg)
					  )
					)
				  )
				)
			  (when update-detail-buffer-request
				(pop-to-buffer eshark-detail-buffer)
				(unless eshark-auto-switch-to-detail-buffer
				  (pop-to-buffer eshark-buffer-name)
				  )
				)
			  )
			)
		  )
		 )
		)
	  )
	)
  )

(defface eshark-cur-hex-face  '((t :inherit highlight :extend t))
  "Default face used for hex with respect of current packet portion."
  :group 'basic-faces)

(defun eshark-highlight-hex-portion(pos size)
  (with-current-buffer eshark-hex-buffer
	(save-excursion
	(setq buffer-read-only nil)
	(set-text-properties (point-min) (point-max) nil)
	(let (
		  (line (1+ (/ pos 16)))
		  (col (% pos 16))
		  hl-pos
		  )
	  (goto-char (point-min))
	  (forward-line (1- line))
	  (forward-char (+ 6 (* 3 col)))
	  (setq hl-pos (pos-bol))
	  
	  (while (> size 0)
		(let* (
			   (hex-cnt (if (> (+ col size) 16) (- 16 col) size))
			   )
		  (set-text-properties (point) (+ (point) (+ 2 (* 3 (1- hex-cnt)))) '(face eshark-cur-hex-face))
		  (cl-decf size hex-cnt)
		  (when (> size 0)
			(forward-line)
			(forward-char 6))
		  (setq col 0)
		  )
		)
	  (setq buffer-read-only t)
	  (if (null (pos-visible-in-window-p hl-pos (get-buffer-window) 'partially))
		  (set-window-start (get-buffer-window) hl-pos nil)
		)
	  )
	)
	)
  )
;; (defvar eshark-hex-buffer-str "")
(defvar eshark-pkt-hex-lastest-number nil)
(defvar zyt-sniffer--vier-pkt-hex-timer (timer-create))
(defun eshark-view-pkt-hex(frame-number frames-only &optional highlight-pos highlight-size)
  (setq eshark-pkt-hex-lastest-number frame-number)
  (let (
		(cur-buffer (current-buffer))
		(eshark-hex-buffer-str "")
		)
	(with-current-buffer (or eshark-hex-buffer (setq eshark-hex-buffer (get-buffer-create eshark-frame-hex-buffer-name)))
	  (setq buffer-read-only nil)
	  ;; (erase-buffer)
	  (make-process
	   :name "net packet hexdump process"
	   :buffer nil;;(current-buffer)
	   :command (list "sh" "-c" (format "tshark -r %s --hexdump delimit --hexdump %s -Y \"frame.number==%d\"" tshark-capture-temp-file (if frames-only "frames" "all") frame-number))
	   :coding 'chinese-gb18030-dos
	   :stdrrr (get-buffer-create "*Packet hexdump err*")
	   :filter
	   ;; [[**  (bookmark--jump-via "("(elisp) Filter Functions" (front-context-string . "File: elisp.info") (rear-context-string) (position . 3314736) (last-modified 26444 6735 918922 0) (filename . "d:/Software/Editor/Emacs/emacs-29.4/share/info/elisp") (info-node . "Filter Functions") (handler . Info-bookmark-jump) (defaults "(elisp) Filter Functions" "elisp" "Filter Functions" "*info*"))" 'switch-to-buffer-other-window)  **]]
	   (lambda (proc string)
		 ;; (when (buffer-live-p (process-buffer proc))
		 (when (buffer-live-p eshark-hex-buffer)
		   (display-buffer eshark-hex-buffer)
		   (with-current-buffer eshark-hex-buffer
			 ;; (setq buffer-read-only nil)
			 ;; (erase-buffer)
			 (if frames-only
				 ;; (insert string)
				 (setq eshark-hex-buffer-str (concat eshark-hex-buffer-str string))
			   (setq eshark-hex-buffer-str (concat eshark-hex-buffer-str string))
			   ;; (insert string)
			   ;; (insert (progn (string-match "Reassembled TCP ([[:digit:]]++ bytes):\n\\(\\(.\\|\n\\)*\\)" string) (match-string 1 string)))
			   )
			   (message "eshark-hex-buffer-str len->%d" (length eshark-hex-buffer-str))
			 ;; (setq buffer-read-only t)
			 )
		   )
		 )
	   :sentinel
	   ;; #'zyt-sentinal
	   ;; [[**  (bookmark--jump-via "("Remove 'Process finished' message" (filename . "~/org-roam-files/20241201163551-make_process.org") (front-context-string . "* eliminate 'Pro") (rear-context-string . "e: make-process\n") (position . 90) (last-modified 26444 8436 527173 0) (defaults "org-capture-last-stored" "20241201163551-make_process.org"))" 'switch-to-buffer-other-window)  **]] 
	   ;; #'ignore
	   (lambda(proc evt-string)
		 ;; (if (string= evt-string "finished\n")
			 ;; (setq zyt-sniffer--vier-pkt-hex-timer nil))
		 (when (and
				(= eshark-pkt-hex-lastest-number frame-number)
				(string= evt-string "finished\n"))
		   (let ((inhibit-message t))
			 (message "finished frame-number--->%d" frame-number)
			 )
		   ;; (with-current-buffer (process-buffer proc)
		   (unless frames-only
			 (setq eshark-hex-buffer-str
				   (progn
					 (string-match "Reassembled TCP ([[:digit:]]++ bytes):\n\\(\\(.\\|\n\\)*\\)" eshark-hex-buffer-str)
					 (match-string 1 eshark-hex-buffer-str)
					 ))
			 )
		   (with-current-buffer eshark-hex-buffer
			 (setq buffer-read-only nil)
			 (erase-buffer)
			 (insert eshark-hex-buffer-str)
			 (if (and highlight-pos highlight-size)
				 (eshark-highlight-hex-portion highlight-pos highlight-size)
			   )
			 (setq buffer-read-only t)
			 (if frames-only
				 (rename-buffer (concat eshark-frame-hex-buffer-name ":" (number-to-string frame-number)))
			   (rename-buffer (concat eshark-reassembled-hex-buffer-name  ":" (number-to-string frame-number))))
			 )
		   )
		 )
	   )
	  (unless eshark-auto-switch-to-detail-buffer
		(pop-to-buffer cur-buffer)
		)
	  )
	)
  )

(defun eshark--get-current-frame-number(buffer)
  "Get the frame number of current line, only works in list and detail buffer"
  (pcase buffer
	('list-buffer
	 (with-current-buffer eshark-buffer-name
	   (save-excursion
		 (if-let (
				  (line (thing-at-point 'line))
				  (match (progn
						   (string-match eshark--buffer-frame-number-regexp line)
						   (match-string 1 line)))
				  )
			 (string-to-number match)
		   0
		   )
		 )
	   ))
	('detail-buffer
	 (with-current-buffer eshark-detail-buffer
	   (let ((cnt 1)
			 (backward t)
			 frame-number)
		 (save-excursion
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
		   )
		 (if frame-number (string-to-number frame-number))
		 )
	   )
	 )
	(_ (error "Unknown buffer %s" buffer))
	)
  )

(defun eshark-view-pkt-content(&optional switch-to-detail-buffer target-frame-number)
  "Pop out the detail info of frame on cursor; If `SWITCH-TO-DETAIL-BUFFER` is not nil, jump to the detail info buffer "
  (interactive)
  (setq eshark-auto-switch-to-detail-buffer switch-to-detail-buffer)
  (if-let (
		   (cur-buffer (current-buffer))
		   (frame-number (or target-frame-number (eshark--get-current-frame-number 'list-buffer)))
		   (proto-list (eshark-get-pdml frame-number tshark-capture-temp-file))
		   )
	  (with-current-buffer (setq eshark-detail-buffer (get-buffer-create eshark-packet-pdml-buffer-name))
		  (setq buffer-read-only nil)
		  (erase-buffer)
		  (--map
		   (insert (assemble-proto it))
		   proto-list)
		  (setq buffer-read-only t)
		  (eshark-detail-minor-mode)
		  (goto-char 1)
		  (progn
			(cancel-timer zyt-sniffer--vier-pkt-hex-timer)
			(setq zyt-sniffer--vier-pkt-hex-timer
				  (run-at-time sniffer-view-hex-timer-delay nil
							   #'eshark-view-pkt-hex
							   frame-number
							   'frames-only
							   ))
			)
		  (unless eshark-auto-switch-to-detail-buffer
			(pop-to-buffer cur-buffer)
			)
		)
	(setq eshark-target-frame-number frame-number)
	(eshark--retrive-pdml-bg frame-number 'update-detail-buffer-request)
	(setq sniffer-view-detail-timer-delay 0.2)
	)
  )
(defun eshark--detail-mode-next-frame(&optional arg)
  ;; (interactive "^p\np")
  (interactive)
  (or arg (setq arg 1))
  (let (
		(cur-frame-number (eshark--get-current-frame-number 'detail-buffer))
		(cur-line (line-number-at-pos))
		(cur-buffer (current-buffer))
		)
	(when (> (+ cur-frame-number arg) 0)
	  (eshark-view-pkt-content nil (+ cur-frame-number arg))
	  (goto-line cur-line)
	  (when (and eshark--follow-mode (get-buffer-window eshark-buffer-name))
		(let (
			  (sniffer-buffer-frame-number (eshark--get-current-frame-number 'list-buffer))
			  )
		  (pop-to-buffer eshark-buffer-name)
		  (let (eshark--follow-mode)
			(next-line (- cur-frame-number sniffer-buffer-frame-number (- arg)))
			)
		  (hl-line-mode)
		  (pop-to-buffer cur-buffer)
		  )
		)
	  )
	)
  )

(defun eshark-toggle-follow-mode()
  "Toggle eshark follow mode"
  (interactive)
  (setq eshark--follow-mode (not eshark--follow-mode))
  )
(defconst filter-choice-alist
  '(
	("选中" . yes)
	("非选中" . !)
	("...且选中" . &&)
	("...或选中" . ||)
	("...且不选中" . &&!)
	("...或不选中" . ||!)
	("...清除所有" . clear)
	))
(defun eshark-select-filter()
  ;; eshark-display-filter
  (interactive)
  (when-let (
			 (cur-buffer (current-buffer))
			 (name (get-text-property (point) 'name))
			 (show (get-text-property (point) 'show))
			 (choice
			  ;; [[**  (bookmark--jump-via "("completing-read demo" (filename . "~/org-roam-files/20241201232505-completing_read_demo.org") (front-context-string . "\n[[https://www.h") (rear-context-string . "eting-read demo\n") (position . 98) (last-modified 26444 32788 786157 0) (defaults "org-capture-last-stored" "20241201232505-completing_read_demo.org"))" 'switch-to-buffer-other-window)  **]] 
			  (alist-get (completing-read
						  ;; (format "准备作为过滤器应用 %s %s==%s:" eshark-display-filter name show)
						  (format "准备作为过滤器应用 %s %s:" eshark-display-filter
								  (let ((candiate (concat name " == " show)))
									(set-text-properties 0 (length candiate) '(face eshark-cur-hex-face)
														 candiate)
									candiate
									))
						  filter-choice-alist
						  (lambda(arg)
							(if	(or
								 (null eshark-display-filter)
								 (string= "" eshark-display-filter))
								(member (cdr arg) '(yes !))
							  t
							  )
							)
						  nil
						  nil
						  t
						  ;; 'equal
						  )
						 filter-choice-alist
						 nil
						 nil
						 'string=
						 ))
			 )
	(message "choice-->%s" choice)
	(custom-set-variables
	 (list 'eshark-display-filter
		   (pcase choice
			 ('clear "")
			 ('yes (concat "(" name " == " show ")"))
			 ('! (concat "!(" name " == " show ")"))
			 (_ (concat eshark-display-filter (if (eq 'yes choice) "" (symbol-name choice)) "(" name " == " show ")"))
			 )
		   ))
	)
  )
(defun eshark-doc-lookup()
  (interactive)
  (when-let (
		   (cur-buffer (current-buffer))
		   (name (get-text-property (point) 'name))
		   (url (concat "https://www.wireshark.org/docs/dfref/" (substring name 0 1) "/"
						(nth 0 (split-string name "\\."))
						".html"
						"#"
						name))
		   ;; https://www.wireshark.org/docs/dfref/t/tcp.html#tcp.dstport
		   ;; https://www.wireshark.org/docs/dfref/i/ip.html#ip.flags
		   ;; https://www.wireshark.org/docs/dfref/f/frame.html#frame.interface_name
		   ;; https://www.wireshark.org/docs/dfref/t/tls.html#tls.record.content_type
		   ;; https://www.wireshark.org/docs/dfref/e/eth.html#eth.src.lg
		   ;; https://www.wireshark.org/docs/dfref/s/snmp.html
		   ;; https://www.wireshark.org/docs/dfref/u/udp.html#udp.checksum
		   ;; https://www.wireshark.org/docs/dfref/s/snmp.html#snmp.request_id
		   )
	  ;; (browse-url url)
	  ;; eww has some problem in browsing "https://www.wireshark.org"
	  (w3m url)
	(pop-to-buffer cur-buffer)
	)
  )
(defvar eshark-hex-cur-item-properties nil)
(defconst reassemble-name-list '("tcp.segment" "tcp.segments"))
(defun eshark-move-in-detail-buffer()
  (interactive)
  (let* (
		 (basic-event (event-basic-type last-input-event))
		 (name-before-move (get-text-property (point) ' name))
		 (pos-before-move (get-text-property (point) ' pos))
		 (size-before-move (get-text-property (point) ' size))
		 (ch
		  (if (symbolp basic-event)
			  (get basic-event 'ascii-character)
			basic-event
			)
		  )
		 )
	(prog1
		(pcase basic-event
		  ((or ?j 'down) (next-logical-line nil t))
		  ((or ?k 'up) (previous-logical-line nil t))
		  ((or ?l 'right) (forward-char))
		  ((or ?h 'left) (forward-char -1))
		  )
	  (when-let (
				 (item-properties (text-properties-at (point)))
				 (pos (get-text-property (point) 'pos))
				 (size (get-text-property (point) 'size))
				 (name (get-text-property (point) ' name))
				 ;; check whether hex buffer is currently displayed is any window
				 (_ (get-buffer-window eshark-hex-buffer))
				 )
		(if (or
			 (xor
			  (member name reassemble-name-list)
			  (s-prefix-p eshark-reassembled-hex-buffer-name (buffer-name eshark-hex-buffer))
			  )
			 (xor
			  (null (member name reassemble-name-list))
			  (s-prefix-p eshark-frame-hex-buffer-name (buffer-name eshark-hex-buffer))
			  )
			 )
			;; [[**  (bookmark--jump-via "("tcp.segment demo" (filename . "~/org-roam-files/sh-qerdjfi.xml") (buffer-name . "sh-qerdjfi.xml") (front-context-string . "=\"tcp.segment\" s") (rear-context-string . "     <field name") (front-context-region-string) (rear-context-region-string) (visits . 0) (time 26445 34534 14238 0) (created 26445 34534 14238 0) (position . 31183))" 'switch-to-buffer-other-window)  **]]
			;; 此种情况会异步刷新hex-buffer，buf内容刷新时间不确定
			;; 故不能在此处调用eshark-highlight-hex-portion，而要在异步process的sentinal中高亮相应部分
			(eshark-view-pkt-hex (eshark--get-current-frame-number 'list-buffer)
								 (null (member name reassemble-name-list))
								 (string-to-number pos) (string-to-number size))         
		  (eshark-highlight-hex-portion (string-to-number pos) (string-to-number size))
		  )
		)
	  )
	)
  )
(defvar zyt/real-time-sniff-detail-mode-map
  (let ((map (make-sparse-keymap)))
	(keymap-set map "q" #'eshark-view-pkt-content-quit)
	(keymap-set map "<tab>" #'outline-cycle)
	(keymap-set map "C-j" (lambda()(interactive)(eshark--detail-mode-next-frame 1)))
	(keymap-set map "C-k" (lambda()(interactive)(eshark--detail-mode-next-frame -1)))
	(keymap-set map "C-c C-f" #'eshark-toggle-follow-mode)
	(keymap-set map "<backtab>" #'outline-cycle-buffer)
	(keymap-set map "f" (lambda()(interactive)
						  ;; (prinl (get-text-property (point) 'name))
						  (prin1 (text-properties-at (point)))
						  (eshark-select-filter)
						  (if-let (
								   (pos (get-text-property (point) 'pos))
								   (size (get-text-property (point) 'size))
								   )
							  (if (> (string-to-number size) 0)
							  (eshark-highlight-hex-portion (string-to-number pos) (string-to-number size))
							  )
							)))
	(keymap-set map "h" #'eshark-move-in-detail-buffer)
	(keymap-set map "j" #'eshark-move-in-detail-buffer)
	(keymap-set map "k" #'eshark-move-in-detail-buffer)
	(keymap-set map "l" #'eshark-move-in-detail-buffer)
	(keymap-set map "<left>" #'eshark-move-in-detail-buffer)
	(keymap-set map "<right>" #'eshark-move-in-detail-buffer)
	(keymap-set map "<down>" #'eshark-move-in-detail-buffer)
	(keymap-set map "<up>" #'eshark-move-in-detail-buffer)
	(keymap-set map "C-c f" #'eshark-doc-lookup)
	map
	)
  )
(define-minor-mode eshark-detail-minor-mode
  "eshark detail content minor mode"
  :lighter " N&D"
  :keymap zyt/real-time-sniff-detail-mode-map
  (progn
	(outline-minor-mode -1) ;;Reset to normal-mode to reset `underlying face`to avoid resizing :height/:wight relatively to current value each time when entering eshark-detail-minor-mode.
	;; (setq-local outline-regexp "\\(^\\w\\)\\|\\(^ \\{4,64\\}\\)")
	(setq-local outline-regexp "\\(^\\w\\{1,1\\}\\)\\|\\(^\s\\{4,16\\}\\)")
	;; (face-spec-set 'outline-1 '((t (:extend t :foreground "yellow" :weight bold :height 1.1))))
	;; (face-spec-set 'outline-4 '((t (:extend t :foreground "steel blue" :weight bold :height 1))))
	;; (face-spec-set 'outline-8 '((t (:extend t :foreground "red" :slant italic :weight thin :height 1))))
	;; (face-spec-set 'outline-16 '((t (:extend t :foreground "red" :slant italic :weight thin :height 1))))
	(setq-local outline-minor-mode-highlight  t)
	(setq buffer-read-only t)
	(outline-minor-mode)
	;; (outline-hide-sublevels 1)
	;; (outline-hide-sublevels 2)
	)  
  )


(advice-add
 'eshark-view-pkt-content
 :around #'advice-coding-wrapper
 )
;; (advice-remove 'eshark-view-pkt-content #'advice-coding-wrapper)
(defun eshark-view-pkt-content-quit()
  (interactive)
  (kill-buffer)
  )
(defvar eshark--follow-mode nil)

(defvar zyt-sniffer--vier-pkt-details-timer nil)
(defun eshark-line-move-wrapper(orig &rest args)
  "为 eshark 的follow模式特殊处理"
  (prog1
	  (apply orig args)
	(when (and zyt/real-time-sniff-minor-mode eshark--follow-mode)
	  (if zyt-sniffer--vier-pkt-details-timer
		  (cancel-timer zyt-sniffer--vier-pkt-details-timer))
	  (if sniffer-view-detail-timer-delay
		  (setq zyt-sniffer--vier-pkt-details-timer
				(run-at-time sniffer-view-detail-timer-delay nil
							 (lambda()
							   (let ((cur-buffer (current-buffer)))
								 (eshark-view-pkt-content nil nil)
								 (pop-to-buffer cur-buffer)
								 ))
							 ))
		(let ((cur-buffer (current-buffer)))
		  (eshark-view-pkt-content nil nil)
		  (pop-to-buffer cur-buffer)
		  )
		)
	  )
	)
  )
(advice-add
 'line-move
 :around
 'eshark-line-move-wrapper
 )
;; [[**  (bookmark--jump-via "("Tshark | Display Filters" (front-context-string . "\n\nIntroduction t") (rear-context-string . "od introduction.") (position . 3724) (last-modified 26438 53980 855528 0) (filename . "https://tshark.dev/analyze/packet_hunting/packet_hunting/") (url . "https://tshark.dev/analyze/packet_hunting/packet_hunting/") (handler . bookmark-w3m-bookmark-jump) (defaults "Tshark | Display Filters" "*w3m*"))" 'switch-to-buffer-other-window)  **]]
(defvar zyt/real-time-sniff-mode-map
  (let ((map (make-sparse-keymap)))
	(keymap-set map "<return>"
				(lambda()
				  "Show details of selected packet"
				  (interactive)
				  (eshark-view-pkt-content 'switch-to-detail-buffer)))
	(keymap-set map "C-c C-f" #'eshark-toggle-follow-mode)
	(keymap-set map "s" #'eshark-stop)
	(keymap-set map "t" #'eshark-toggle)
	map
	)
  )

(define-minor-mode zyt/real-time-sniff-minor-mode
  "Sniff network packets in real time"
  :init-value nil
  :lighter "Sniff"
  :keymap zyt/real-time-sniff-mode-map
  (setq eshark--follow-mode t) 
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

(defun eshark-find-frame(frame-number)
  (let (found)
	(save-excursion
	  (let ((current-frame-number
			 (eshark--get-current-frame-number 'detail-buffer))
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
(defun eshark-narrow-frame (frame-number)
  "Find target frame indexed by frame-number, narrow region and return the start point; Return nil if not found"
  (let* (
		 (cur-start (point-min))
		 (cur-end (point-max))
		 (cur-point (point))
		 (nop   (widen))
		 (start (eshark-find-frame frame-number))
		 (end (eshark-find-frame (1+ frame-number)))
		 )
	(if start
		(narrow-to-region start (or end (point-max)))
	  (narrow-to-region cur-start cur-end)
	  (goto-char cur-point)
	  )
	start
	)
  )
(provide 'eshark)
