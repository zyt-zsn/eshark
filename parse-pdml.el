;;; -*- lexical-binding: t -*-

(require 'dom)
(require 'dash)

(defun disp-field (field depth)
  (let (
		(tab-cnt depth)
		)
	(while (> tab-cnt 0)
	  (princ "\t")
	  (cl-decf tab-cnt)
	  ))
  (princ (dom-attr field 'showname))
  (princ "\n")
  (if (dom-children field)
	  (--map
	   (disp-field it (1+ depth))
	   (dom-children field)
	   )
	)
  )
(defconst stream-list '("eth" "ip" "tcp" "udp" "http"))
(defvar eth-stream-index nil)
(defvar ip-stream-index nil)
(defvar tcp-stream-index nil)
(defvar udp-stream-index nil)
(defun assemble-field (field depth)
  (let (
		(text "")
		children-str-list
		(tab-cnt depth)
		)
	
	(let* (
		  (showname (dom-attr field 'showname))
		  (show (dom-attr field 'show))
		  (name (dom-attr field 'name))
		  (proto-name (nth 0 (string-split name "\\.")))
		  (size (dom-attr field 'size))
		  )
	  (if (and name (string-suffix-p "stream" name) (member proto-name stream-list))
		  (set (intern (concat proto-name "-stream-index")) (string-to-number (dom-attr field 'show)))
		  )
	  (setq text (concat text
						 (if (and showname (null (string= "" showname)))
							 showname
						   (if (and show (null (string= "" show)))
							   show
							 name))
						 ))
	  (if (string= "0" size)
		  (setq text (concat "[" text "]"))
		)
	  (while (> tab-cnt 0)
		(setq text (concat "\s\s\s\s" text))
		(cl-decf tab-cnt)
		)
	  )
	(setq text (concat text "\n"))
	
	;; [[**  (bookmark--jump-via "("field with children" (filename . "d:/temp/sh-xxxxxx.xml") (front-context-string . "    <field name=") (rear-context-string . "0\" value=\"45\"/>\n") (position . 25006) (last-modified 26443 55670 875035 0) (defaults "sh-xxxxxx.xml"))" 'switch-to-buffer-other-window)  **]]	
	(set-text-properties 0 (length text)
						 `(
						   show ,(dom-attr field 'show)
						   value,(dom-attr field 'value)
						   size,(dom-attr field 'size)
						   pos,(dom-attr field 'pos)
						   name ,(dom-attr field 'name)
						   ) text)
	(when (dom-children field)
	  (setq children-str-list
			(--keep
			 (assemble-field it (1+ depth))
			 (dom-children field)
			 )
			)
	  (--map
	   (setq text (concat text it))
	   children-str-list
	   )
	  )
	;; (setq text (propertize text 'face '(:box t) 'mouse-face 'bold-italic))
	text
	)
  )
(defvar http-prot nil)
(defun assemble-proto (proto)
;; [[**  (bookmark--jump-via "("proto sample" (filename . "d:/temp/sh-xxxxxx.xml") (front-context-string . "  <proto name=\"i") (rear-context-string . "0\"/>\n  </proto>\n") (position . 24664) (last-modified 26443 55593 550900 0) (defaults "sh-xxxxxx.xml"))" 'switch-to-buffer-other-window)  **]]
  (let* (
		 (showname (dom-attr proto 'showname))
		 (show (dom-attr proto 'show))
		 (name (dom-attr proto 'name))
		 (text (or showname show name))
		 (value (dom-attr proto 'value))
		 (size (dom-attr proto 'size))
		 (pos (dom-attr proto 'pos))

		 (proto-fg-color "yellow")
		 (field-list (dom-children proto))
		 (coding-system-for-write 'chinese-gb18030-dos)
		 field-str-list
		 )
	(when (string= name "http")
	  (setq http-prot t) 
	  )
	(set-text-properties 0 (length text) '(name "test") text)
	(set-text-properties 0 (length text)
						 `(
						   show ,show
						   value ,value
						   size ,size
						   pos ,pos
						   name ,name
						   ) text)

	(setq text (propertize text 'face `(:foreground ,proto-fg-color) 'mouse-face 'bold-italic))
	(setq text (concat text "\n"))
	(setq field-str-list
		  (--keep
		   (assemble-field it 1)
		   field-list
		   ))
	(--map
	 (setq text (concat text it))
	 field-str-list
	 )
	text
	)
  )
(defun assemble-proto-list (proto-list)
  (let ((ret ""))
	(--map
	 (set (intern (concat it "-stream-index")) nil)
	 stream-list
	 )
	(setq http-prot nil)
	(--map
	 (progn
	   (setq ret (concat ret (assemble-proto it)))
	   )
	 proto-list)
	(--map
	 (when-let (
				(stream-index
				(symbol-value (intern (concat it "-stream-index"))))
				)
	   (add-text-properties 0 (length ret) (list (intern (concat it "-stream-index")) stream-index) ret)
	   (when http-prot
		 (add-text-properties 0 (length ret) (list (intern "http-stream-index") stream-index) ret)
		 )
	   )
	 '("tcp" "udp"))
	ret
	)
  )
;; (assemble-proto (nth 1 proto-list))

(defun disp-proto (proto)
  (print (assemble-proto proto)
		 )
  )
;; (disp-proto (nth 1 proto-list))

(provide 'parse-pdml)
