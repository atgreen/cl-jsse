;;;; pure-tls.lisp --- pure-tls API implemented over cl-jsse.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A drop-in for pure-tls's public API, backed by JSSE.  Where pure-tls takes
;;;; PEM material and JSSE wants a key store, PEM options are refused with a
;;;; message pointing at the :KEYSTORE / :TRUSTSTORE extensions rather than
;;;; silently ignored.  ECH, ACME, and post-quantum features are out of scope.

(in-package #:pure-tls)

;;;; Conditions

(define-condition tls-error (error)
  ((message :initarg :message :initform nil :reader tls-error-message))
  (:report (lambda (c s) (format s "TLS error: ~A" (tls-error-message c)))))

(define-condition tls-handshake-error (tls-error) ())
(define-condition tls-certificate-error (tls-error) ())
(define-condition tls-verification-error (tls-error) ())
(define-condition tls-alert-error (tls-error) ())

;;;; Verification modes and cipher-suite names

(defconstant +verify-none+ 0)
(defconstant +verify-peer+ 1)
(defconstant +verify-required+ 2)

(defparameter +tls-aes-128-gcm-sha256+ "TLS_AES_128_GCM_SHA256")
(defparameter +tls-aes-256-gcm-sha384+ "TLS_AES_256_GCM_SHA384")
(defparameter +tls-chacha20-poly1305-sha256+ "TLS_CHACHA20_POLY1305_SHA256")

;;;; Configuration

(defvar *default-buffer-size* 16384
  "Compatibility only; the engine sizes its own buffers.")
(defvar *default-verify-mode* +verify-required+)
(defvar *default-tls-context* nil
  "The context used when a stream constructor is given none.")

;;;; Types.  cl-jsse's gray-stream classes stand in for pure-tls's.

(deftype tls-stream () 'cl-jsse:jsse-stream)
(deftype tls-client-stream () 'cl-jsse:jsse-client-stream)
(deftype tls-server-stream () 'cl-jsse:jsse-server-stream)

;;;; Context

(defun make-tls-context (&key (verify-mode +verify-required+)
                              verify-depth
                              certificate-chain-file
                              private-key-file
                              ca-file
                              ca-directory
                              cipher-suites
                              alpn-protocols
                              protocols
                              (auto-load-system-ca t)
                              hostname-policy
                              ;; cl-jsse (JSSE-native) extensions:
                              keystore keystore-password truststore truststore-password
                              (check-hostname t))
  "Create a TLS context (a cl-jsse context).

   PEM CERTIFICATE-CHAIN-FILE / PRIVATE-KEY-FILE / CA-FILE / CA-DIRECTORY are
   refused: JSSE uses key stores, so pass a PKCS12 :KEYSTORE (identity) and/or
   :TRUSTSTORE (CAs).  Without a trust store, verification uses the system CAs."
  (declare (ignore verify-depth auto-load-system-ca hostname-policy))
  (when (or certificate-chain-file private-key-file)
    (error 'tls-certificate-error
           :message "pure-tls over JSSE: PEM :CERTIFICATE-CHAIN-FILE / :PRIVATE-KEY-FILE are ~
not supported; supply a PKCS12 :KEYSTORE and :KEYSTORE-PASSWORD."))
  (when (or ca-file ca-directory)
    (error 'tls-certificate-error
           :message "pure-tls over JSSE: PEM :CA-FILE / :CA-DIRECTORY are not supported; pass ~
a PKCS12 :TRUSTSTORE, or rely on the system CAs."))
  (cl-jsse:make-context :verify-mode verify-mode
                        :keystore keystore :keystore-password keystore-password
                        :truststore truststore :truststore-password truststore-password
                        :alpn-protocols alpn-protocols
                        :protocols protocols
                        :cipher-suites cipher-suites
                        :check-hostname check-hostname))

(defun tls-context-free (context)
  (cl-jsse:context-free context))

(defmacro with-tls-context ((context &key auto-free-p) &body body)
  (let ((ctx (gensym)))
    `(let* ((,ctx ,context)
            (*default-tls-context* ,ctx))
       (unwind-protect (progn ,@body)
         (when ,auto-free-p (tls-context-free ,ctx))))))

;;;; Per-verify default client contexts (see the note in cl+ssl.lisp)

(defvar *client-contexts* (make-hash-table))

(defun %client-context-for (verify)
  (or (gethash verify *client-contexts*)
      (setf (gethash verify *client-contexts*)
            (cl-jsse:make-context :verify-mode verify
                                  :check-hostname (= verify +verify-required+)))))

;;;; Streams

(defun make-tls-client-stream (socket &key
                                        hostname
                                        sni-hostname
                                        context
                                        (verify nil verify-supplied-p)
                                        alpn-protocols
                                        cipher-suites
                                        client-certificate
                                        client-key
                                        ech-configs
                                        (ech-enabled t)
                                        close-callback
                                        external-format
                                        (buffer-size *default-buffer-size*)
                                        max-send-fragment
                                        request-context)
  "Open a TLS client stream over SOCKET.  CLIENT-CERTIFICATE / CLIENT-KEY (mTLS)
and ECH are not supported here."
  (declare (ignore sni-hostname cipher-suites ech-enabled external-format
                   buffer-size max-send-fragment request-context))
  (when (or client-certificate client-key)
    (error 'tls-error
           :message "pure-tls over JSSE: mTLS via :CLIENT-CERTIFICATE / :CLIENT-KEY is not ~
wired through this layer; use a cl-jsse context with a client :KEYSTORE."))
  (when ech-configs
    (error 'tls-error :message "pure-tls over JSSE: ECH (:ECH-CONFIGS) is out of scope."))
  (cl-jsse:start)
  (let* ((verify-mode (if verify-supplied-p
                          (etypecase verify
                            (null +verify-none+)
                            (integer verify))
                          *default-verify-mode*))
         (ctx (or context *default-tls-context* (%client-context-for verify-mode))))
    (cl-jsse:make-client-stream socket
                                :context ctx
                                :hostname hostname
                                :alpn-protocols alpn-protocols
                                :close-callback close-callback)))

(defun make-tls-server-stream (socket &key
                                        context
                                        certificate
                                        key
                                        (verify +verify-none+)
                                        trust-store
                                        alpn-protocols
                                        sni-callback
                                        certificate-provider
                                        cipher-suites
                                        close-callback
                                        external-format
                                        (buffer-size *default-buffer-size*)
                                        max-send-fragment
                                        request-context)
  "Open a TLS server stream over SOCKET.  The identity must come from a cl-jsse
CONTEXT with a :KEYSTORE; PEM :CERTIFICATE / :KEY are refused."
  (declare (ignore trust-store cipher-suites external-format buffer-size
                   max-send-fragment request-context))
  (when (or certificate key)
    (error 'tls-certificate-error
           :message "pure-tls over JSSE: PEM :CERTIFICATE / :KEY are not supported; supply a ~
cl-jsse context with a PKCS12 :KEYSTORE."))
  (when (or sni-callback certificate-provider)
    (error 'tls-error
           :message "pure-tls over JSSE: :SNI-CALLBACK / :CERTIFICATE-PROVIDER are not supported."))
  (let ((ctx (or context *default-tls-context*
                 (error 'tls-error
                        :message "pure-tls over JSSE: MAKE-TLS-SERVER-STREAM needs a CONTEXT ~
with the server's key store."))))
    (cl-jsse:make-server-stream socket
                                :context ctx
                                :verify verify
                                :alpn-protocols alpn-protocols
                                :close-callback close-callback)))

(defmacro with-tls-client-stream ((var socket &rest args) &body body)
  `(let ((,var (make-tls-client-stream ,socket ,@args)))
     (unwind-protect (progn ,@body) (close ,var))))

(defmacro with-tls-server-stream ((var socket &rest args) &body body)
  `(let ((,var (make-tls-server-stream ,socket ,@args)))
     (unwind-protect (progn ,@body) (close ,var))))

;;;; Accessors

(defun tls-peer-certificate (stream) (cl-jsse:peer-certificate stream))
(defun tls-peer-certificate-chain (stream) (cl-jsse:peer-certificate-chain stream))
(defun tls-selected-alpn (stream) (cl-jsse:selected-alpn stream))
(defun tls-cipher-suite (stream) (cl-jsse:cipher-suite stream))
(defun tls-version (stream) (cl-jsse:protocol-version stream))
(defun tls-client-hostname (stream) (cl-jsse:client-hostname stream))

;;;; Certificates

(defun certificate-subject-common-names (cert) (cl-jsse:certificate-subject-common-names cert))
(defun certificate-fingerprint (cert &optional (algorithm :sha1))
  (cl-jsse:certificate-fingerprint cert algorithm))
(defun certificate-not-before (cert) (cl-jsse:certificate-not-before cert))
(defun certificate-not-after (cert) (cl-jsse:certificate-not-after cert))
(defun certificate-free (cert) (declare (ignore cert)) nil)
(defun verify-hostname (cert hostname) (cl-jsse:verify-hostname cert hostname))

;;;; Crypto utilities

(defun random-bytes (count)
  "COUNT cryptographically-random bytes, as an (unsigned-byte 8) vector."
  (cl-jsse:start)
  (let* ((rng (cl-jsse::java-new "java.security.SecureRandom" "()"))
         (arr (cl-jsse::%jbyte-array count)))
    (cl-jsse::java-call "nextBytes([B)V" rng arr)
    (cl-jsse::%jbytes->lisp arr count)))
