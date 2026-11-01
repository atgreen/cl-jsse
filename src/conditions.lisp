;;;; conditions.lisp --- Error conditions for cl-jsse.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(in-package #:cl-jsse)

(define-condition jsse-error (error)
  ((message :initarg :message :initform nil :reader jsse-error-message)
   (cause :initarg :cause :initform nil :reader jsse-error-cause
          :documentation "The underlying Java throwable, when one triggered this."))
  (:report (lambda (c s)
             (format s "JSSE error: ~A" (or (jsse-error-message c) "unspecified"))))
  (:documentation "Base condition for all cl-jsse errors."))

(define-condition jsse-handshake-error (jsse-error) ()
  (:documentation "The TLS handshake failed."))

(define-condition jsse-verification-error (jsse-error) ()
  (:documentation "Peer certificate verification failed (bad chain, untrusted
CA, hostname mismatch, expired cert, ...)."))

(define-condition jsse-certificate-error (jsse-error) ()
  (:documentation "A certificate or key could not be loaded or decoded."))
