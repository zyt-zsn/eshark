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
(defun assemble-field (field depth)
  (let (
	(text "")
		children-str-list
		(tab-cnt depth)
		)
	(while (> tab-cnt 0)
	  ;; (princ "\t")
	  (setq text (concat text "\t"))
	  (cl-decf tab-cnt)
	  )
	(let (
		  (showname (dom-attr field 'showname))
		  (show (dom-attr field 'show))
		  (name (dom-attr field 'name))
		  )
	  (setq text (concat text
						 (if (and showname (null (string= "" showname)))
							 showname
						   (if (and show (null (string= "" show)))
							   show
							 name))
						 ))
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
(defun assemble-proto (proto)
;; [[**  (bookmark--jump-via "("proto sample" (filename . "d:/temp/sh-xxxxxx.xml") (front-context-string . "  <proto name=\"i") (rear-context-string . "0\"/>\n  </proto>\n") (position . 24664) (last-modified 26443 55593 550900 0) (defaults "sh-xxxxxx.xml"))" 'switch-to-buffer-other-window)  **]]
  (let* (
		 (text (or (dom-attr proto 'showname) (dom-attr proto 'show) (dom-attr proto 'name)))
		 field-str-list
		 (proto-fg-color "yellow")
		 (field-list (dom-children proto))
		 (coding-system-for-write 'chinese-gb18030-dos)
		 )
	(set-text-properties 0 (length text) '(name "test") text)
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

;; (assemble-proto (nth 1 proto-list))

(defun disp-proto (proto)
  (print (assemble-proto proto)
		 )
  )
;; (disp-proto (nth 1 proto-list))

(provide 'parse-pdml)
