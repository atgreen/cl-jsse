;;;; cl+ssl.lisp --- cl+ssl API implemented over cl-jsse.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Follows pure-tls's cl+ssl-compat pattern: options that are genuinely
;;;; meaningless for this stack are ignored silently, but a security-relevant
;;;; option we cannot honour is an error rather than a silent no-op -- quietly
;;;; dropping a verify-callback or an encrypted-key password would weaken a
;;;; caller that relied on it.
;;;;
;;;; JSSE configures identity and trust through key stores, not the PEM files
;;;; cl+ssl takes, so PEM certificate/key options are refused with a message
;;;; pointing at the JSSE-native :KEYSTORE / :TRUSTSTORE extensions.

(in-package #:cl+ssl)

;;;; Conditions

(define-condition ssl-error (error)
  ((message :initarg :message :initform nil :reader ssl-error-message))
  (:report (lambda (c s) (format s "SSL error: ~A" (ssl-error-message c)))))

(define-condition ssl-error-verify (ssl-error)
  ((stream :initarg :stream :initform nil :reader ssl-error-stream)
   (error-code :initarg :error-code :initform nil :reader ssl-error-code))
  (:report (lambda (c s) (format s "SSL verification error (code ~A)" (ssl-error-code c)))))

(define-condition ssl-error-initialize (ssl-error)
  ((reason :initarg :reason :initform nil :reader ssl-error-reason))
  (:report (lambda (c s) (format s "SSL initialization error: ~A" (ssl-error-reason c)))))

;;;; Constants (for source compatibility)

(defconstant +ssl-verify-none+ 0)
(defconstant +ssl-verify-peer+ 1)
(defconstant +ssl-verify-fail-if-no-peer-cert+ 2)
(defconstant +ssl-verify-client-once+ 4)

(defconstant +ssl-op-no-sslv2+ #x01000000)
(defconstant +ssl-op-no-sslv3+ #x02000000)
(defconstant +ssl-op-no-tlsv1+ #x04000000)
(defconstant +ssl-op-no-tlsv1-1+ #x10000000)
(defconstant +ssl-op-no-tlsv1-2+ #x08000000)

(defconstant +ssl-sess-cache-off+ #x0000)
(defconstant +ssl-sess-cache-client+ #x0001)
(defconstant +ssl-sess-cache-server+ #x0002)
(defconstant +ssl-sess-cache-both+ #x0003)
(defconstant +ssl-sess-cache-no-auto-clear+ #x0080)
(defconstant +ssl-sess-cache-no-internal-lookup+ #x0100)
(defconstant +ssl-sess-cache-no-internal-store+ #x0200)
(defconstant +ssl-sess-cache-no-internal+ #x0300)

;;;; Defaults

(defvar *default-cipher-list* nil
  "Default cipher list (TLS 1.3 ignores it; kept for compatibility).")
(defvar *default-buffer-size* 2048
  "Default buffer size for SSL streams (unused; the engine sizes its own).")
(defvar *make-ssl-client-stream-verify-default* :required
  "Default verification mode for MAKE-SSL-CLIENT-STREAM.")
(defvar *default-unwrap-stream-p* t
  "Compatibility only; not used.")

;;;; Global context

(defvar *ssl-global-context* nil
  "The global SSL context (a cl-jsse context).")

(defun ensure-initialized (&key method)
  "Bring the global context up if it is not already.  No OpenSSL to load, so
this only makes the default context."
  (declare (ignore method))
  (cl-jsse:start)
  (unless *ssl-global-context*
    (setf *ssl-global-context* (make-context)))
  t)

(defun reload ()
  "Drop the global context (it is rebuilt on next use)."
  (setf *ssl-global-context* nil)
  t)

;;;; Context

(defun %keystore-file-p (path)
  (let ((type (pathname-type (pathname path))))
    (and type (member type '("p12" "pfx" "jks" "keystore") :test #'string-equal))))

(defun make-context (&key method
                          disabled-protocols
                          options
                          min-proto-version
                          session-cache-mode
                          (verify-location :default)
                          (verify-depth 100)
                          (verify-mode +ssl-verify-peer+)
                          verify-callback
                          cipher-list
                          pem-password-callback
                          certificate-chain-file
                          private-key-file
                          private-key-password
                          private-key-file-type
                          ;; cl-jsse (JSSE-native) extensions:
                          keystore keystore-password truststore truststore-password
                          alpn-protocols protocols cipher-suites)
  "Create an SSL context (a cl-jsse context).

   Options meaningless for this stack are ignored: METHOD, DISABLED-PROTOCOLS,
   OPTIONS, MIN-PROTO-VERSION, SESSION-CACHE-MODE, CIPHER-LIST, VERIFY-DEPTH.

   VERIFY-CALLBACK and encrypted-key options are refused rather than ignored.
   PEM CERTIFICATE-CHAIN-FILE / PRIVATE-KEY-FILE are refused: JSSE uses key
   stores, so pass a PKCS12 :KEYSTORE and :KEYSTORE-PASSWORD instead.  A PKCS12
   VERIFY-LOCATION file is accepted as a trust store; :DEFAULT means the system
   CAs."
  (declare (ignore method disabled-protocols options min-proto-version
                   session-cache-mode cipher-list private-key-file-type verify-depth))
  (when verify-callback
    (error 'ssl-error
           :message "cl+ssl over JSSE: :VERIFY-CALLBACK is not supported.  Ignoring it ~
would silently leave verification at the default trust-store policy, weakening a ~
caller relying on it for pinning or custom chain checks."))
  (when (or pem-password-callback private-key-password)
    (error 'ssl-error
           :message "cl+ssl over JSSE: encrypted private keys (:PEM-PASSWORD-CALLBACK / ~
:PRIVATE-KEY-PASSWORD) are not supported."))
  (when (or certificate-chain-file private-key-file)
    (error 'ssl-error
           :message "cl+ssl over JSSE: PEM :CERTIFICATE-CHAIN-FILE / :PRIVATE-KEY-FILE are ~
not supported; supply a PKCS12 :KEYSTORE and :KEYSTORE-PASSWORD instead."))
  (let ((jsse-verify (cond ((zerop verify-mode) cl-jsse:+verify-none+)
                           ((logtest verify-mode +ssl-verify-fail-if-no-peer-cert+)
                            cl-jsse:+verify-required+)
                           (t cl-jsse:+verify-peer+)))
        (location-truststore
          (cond ((member verify-location '(:default nil) :test #'eql) nil)
                ((and (stringp verify-location) (%keystore-file-p verify-location))
                 verify-location)
                (t (error 'ssl-error
                          :message "cl+ssl over JSSE: a PEM :VERIFY-LOCATION is not ~
supported; pass a PKCS12 :TRUSTSTORE, or :VERIFY-LOCATION :DEFAULT for the system CAs.")))))
    (cl-jsse:make-context
     :verify-mode jsse-verify
     :keystore keystore :keystore-password keystore-password
     :truststore (or truststore location-truststore)
     :truststore-password truststore-password
     :alpn-protocols alpn-protocols
     :protocols protocols :cipher-suites cipher-suites)))

(defun ssl-ctx-free (context)
  "Free an SSL context."
  (cl-jsse:context-free context))

(defun call-with-global-context (ssl-ctx auto-free-p body-fn)
  (ensure-initialized)
  (let ((*ssl-global-context* ssl-ctx))
    (unwind-protect (funcall body-fn)
      (when auto-free-p (ssl-ctx-free ssl-ctx)))))

(defmacro with-global-context ((ssl-ctx &key auto-free-p) &body body)
  `(call-with-global-context ,ssl-ctx ,auto-free-p (lambda () ,@body)))

;;;; Per-verify client contexts
;;;;
;;;; cl+ssl chooses verification per stream, but a JSSE SSLContext bakes its
;;;; trust managers in at creation.  We keep one default client context per
;;;; verify mode (system CAs), built on demand.  A caller that needs a custom
;;;; trust store builds a context with MAKE-CONTEXT and installs it with
;;;; WITH-GLOBAL-CONTEXT, which MAKE-SSL-CLIENT-STREAM uses as-is.

(defvar *client-contexts* (make-hash-table)
  "cl-jsse verify-mode -> a default (system-CA) client context.")

(defun %client-context-for (jsse-verify)
  (or (gethash jsse-verify *client-contexts*)
      (setf (gethash jsse-verify *client-contexts*)
            (cl-jsse:make-context
             :verify-mode jsse-verify
             :check-hostname (= jsse-verify cl-jsse:+verify-required+)))))

;;;; Streams

(defun %ensure-stream (socket-or-fd)
  (etypecase socket-or-fd
    (stream socket-or-fd)
    (integer
     #+sbcl
     (sb-sys:make-fd-stream socket-or-fd :input t :output t
                                         :element-type '(unsigned-byte 8)
                                         :buffering :full :auto-close nil)
     #-sbcl
     (error "file descriptor to stream conversion not implemented for this Lisp"))))

(defun %wrap-close-callback (close-callback)
  "cl+ssl close callbacks take no args; cl-jsse passes the stream."
  (when close-callback
    (lambda (stream) (declare (ignore stream)) (funcall close-callback))))

(defun make-ssl-client-stream (socket &key
                                        (unwrap-stream-p *default-unwrap-stream-p*)
                                        hostname
                                        close-callback
                                        external-format
                                        (verify *make-ssl-client-stream-verify-default*)
                                        alpn-protocols
                                        certificate key password
                                        (cipher-list *default-cipher-list*)
                                        method
                                        (buffer-size *default-buffer-size*)
                                        (input-buffer-size buffer-size)
                                        (output-buffer-size buffer-size))
  "Open an SSL client stream over SOCKET (a stream or a file descriptor).

   VERIFY is :REQUIRED (default), :OPTIONAL, or NIL.  Client-certificate
   authentication via :CERTIFICATE / :KEY is refused here; configure mTLS with a
   cl-jsse context (a client :KEYSTORE) and WITH-GLOBAL-CONTEXT instead."
  (declare (ignore unwrap-stream-p cipher-list method external-format
                   buffer-size input-buffer-size output-buffer-size))
  (when (or certificate key)
    (error 'ssl-error
           :message "cl+ssl over JSSE: client-certificate auth via :CERTIFICATE / :KEY is ~
not wired through this layer; use a cl-jsse context with a client :KEYSTORE."))
  (when password
    (error 'ssl-error :message "cl+ssl over JSSE: encrypted private keys are not supported."))
  (ensure-initialized)
  (let* ((jsse-verify (cond ((null verify) cl-jsse:+verify-none+)
                            ((eql verify :optional) cl-jsse:+verify-peer+)
                            ((eql verify :required) cl-jsse:+verify-required+)
                            (t cl-jsse:+verify-required+)))
         ;; Honour an explicitly-installed custom global context when its verify
         ;; mode matches what this call asks for; otherwise use the per-mode
         ;; default (system CAs).
         (context (if (and *ssl-global-context*
                           (= (cl-jsse::context-verify-mode *ssl-global-context*) jsse-verify))
                      *ssl-global-context*
                      (%client-context-for jsse-verify))))
    (cl-jsse:make-client-stream (%ensure-stream socket)
                                :context context
                                :hostname hostname
                                :alpn-protocols alpn-protocols
                                :close-callback (%wrap-close-callback close-callback))))

(defun make-ssl-server-stream (socket &key
                                        (unwrap-stream-p *default-unwrap-stream-p*)
                                        close-callback
                                        external-format
                                        certificate key password
                                        (verify nil)
                                        alpn-protocols
                                        (cipher-list *default-cipher-list*)
                                        method
                                        (buffer-size *default-buffer-size*)
                                        (input-buffer-size buffer-size)
                                        (output-buffer-size buffer-size))
  "Open an SSL server stream over SOCKET.  The server identity must come from a
cl-jsse context with a :KEYSTORE, installed with WITH-GLOBAL-CONTEXT; PEM
:CERTIFICATE / :KEY are refused.  VERIFY (NIL / :OPTIONAL / :REQUIRED) sets the
client-certificate policy."
  (declare (ignore unwrap-stream-p password cipher-list method external-format
                   buffer-size input-buffer-size output-buffer-size))
  (when (or certificate key)
    (error 'ssl-error
           :message "cl+ssl over JSSE: PEM :CERTIFICATE / :KEY are not supported; supply a ~
cl-jsse context with a PKCS12 :KEYSTORE via WITH-GLOBAL-CONTEXT."))
  (ensure-initialized)
  (unless (and *ssl-global-context* (cl-jsse::context-ssl-context *ssl-global-context*))
    (error 'ssl-error
           :message "cl+ssl over JSSE: MAKE-SSL-SERVER-STREAM needs a global context with ~
the server's key store (see MAKE-CONTEXT :KEYSTORE and WITH-GLOBAL-CONTEXT)."))
  (let ((jsse-verify (cond ((null verify) cl-jsse:+verify-none+)
                           ((eql verify :optional) cl-jsse:+verify-peer+)
                           ((eql verify :required) cl-jsse:+verify-required+)
                           (t cl-jsse:+verify-none+))))
    (cl-jsse:make-server-stream (%ensure-stream socket)
                                :context *ssl-global-context*
                                :verify jsse-verify
                                :alpn-protocols alpn-protocols
                                :close-callback (%wrap-close-callback close-callback))))

;;;; Stream accessors

(defun ssl-stream-x509-certificate (ssl-stream)
  "The peer's leaf X.509 certificate."
  (cl-jsse:peer-certificate ssl-stream))

(defun get-selected-alpn-protocol (ssl-stream)
  "The negotiated ALPN protocol, or NIL."
  (cl-jsse:selected-alpn ssl-stream))

(defgeneric stream-fd (stream)
  (:documentation "The underlying object for STREAM.  Like pure-tls's compat, we
return the stream itself: cl-jsse works with streams, and re-wrapping an
extracted fd would double-buffer.")
  (:method (stream) stream))

;;;; Certificate functions

(defun decode-certificate (format bytes)
  (declare (ignore format bytes))
  (error 'ssl-error :message "cl+ssl over JSSE: DECODE-CERTIFICATE is not yet implemented."))

(defun decode-certificate-from-file (path &key format)
  (declare (ignore path format))
  (error 'ssl-error :message "cl+ssl over JSSE: DECODE-CERTIFICATE-FROM-FILE is not yet implemented."))

(defun x509-free (cert)
  "Free an X.509 certificate (no-op: JSSE objects are GC'd)."
  (declare (ignore cert))
  nil)

(defun certificate-not-after-time (cert) (cl-jsse:certificate-not-after cert))
(defun certificate-not-before-time (cert) (cl-jsse:certificate-not-before cert))
(defun certificate-subject-common-names (cert) (cl-jsse:certificate-subject-common-names cert))
(defun certificate-fingerprint (cert &optional (algorithm :sha1))
  (cl-jsse:certificate-fingerprint cert algorithm))
(defun verify-hostname (cert hostname) (cl-jsse:verify-hostname cert hostname))

;;;; Utilities

(defun random-bytes (count)
  "COUNT cryptographically-random bytes, as an (unsigned-byte 8) vector."
  (cl-jsse:start)
  (let* ((rng (cl-jsse::java-new "java.security.SecureRandom" "()"))
         (arr (cl-jsse::%jbyte-array count)))
    (cl-jsse::java-call "nextBytes([B)V" rng arr)
    (cl-jsse::%jbytes->lisp arr count)))

(defun use-certificate-chain-file (path)
  (declare (ignore path))
  (error 'ssl-error :message "cl+ssl over JSSE: USE-CERTIFICATE-CHAIN-FILE is not supported; ~
use a cl-jsse context with a :KEYSTORE."))

(defun ssl-load-global-verify-locations (&rest pathnames)
  (declare (ignore pathnames))
  (error 'ssl-error :message "cl+ssl over JSSE: SSL-LOAD-GLOBAL-VERIFY-LOCATIONS is not ~
supported; pass a PKCS12 :TRUSTSTORE to MAKE-CONTEXT."))

(defun ssl-set-global-default-verify-paths ()
  "Use the system CAs for the global context (the default already)."
  (ensure-initialized)
  t)

;;;; PEM password

(defvar *pem-password* nil)

(defmacro with-pem-password ((password) &body body)
  `(let ((*pem-password* ,password)) ,@body))

;;;; Deprecated

(defun ssl-check-verify-p ()
  (not (eq *make-ssl-client-stream-verify-default* nil)))

(defun (setf ssl-check-verify-p) (value)
  (setf *make-ssl-client-stream-verify-default* (if value :required nil)))
