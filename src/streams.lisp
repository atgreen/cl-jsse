;;;; streams.lisp --- The gray-stream TLS layer and its constructors.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A JSSE-STREAM is a binary gray stream: reads pull decrypted plaintext from
;;;; the engine pump, writes push plaintext in to be encrypted, and the pump
;;;; does all the TLS over the caller's transport stream underneath.
;;;;
;;;; Trust anchors and whether to verify at all live on the CONTEXT (they are
;;;; the SSLContext's TrustManagers).  Hostname verification and SNI are
;;;; per-stream, set here through SSLParameters.

(in-package #:cl-jsse)

;;;; Turning a context into a configured SSLEngine for one connection

(defun %create-ssl-engine (context &key client hostname alpn verify)
  "Create and configure a javax.net.ssl.SSLEngine from CONTEXT for one
connection.  CLIENT selects client vs server mode; HOSTNAME drives SNI and (for
clients, when the context asks for it) hostname verification; ALPN overrides the
context's protocol list; VERIFY, for servers, overrides the client-certificate
policy (+verify-none+/+verify-peer+/+verify-required+)."
  ;; Everything is set on one SSLParameters object and applied in a single
  ;; setSSLParameters() call.  Setting protocols/ciphers on the engine and then
  ;; applying a separately-fetched SSLParameters would clobber them back to the
  ;; JDK defaults, so all of it goes through PARAMS.
  (let* ((ssl-ctx (context-ssl-context context))
         (e (if (and client hostname)
                (java-call "createSSLEngine(Ljava/lang/String;I)Ljavax/net/ssl/SSLEngine;"
                           ssl-ctx (jstring hostname) 443)
                (java-call "createSSLEngine()Ljavax/net/ssl/SSLEngine;" ssl-ctx)))
         (params (java-call "getSSLParameters()Ljavax/net/ssl/SSLParameters;" e)))
    (java-call "setUseClientMode(Z)V" e (if client 1 0))
    (flet ((string-array (strings)
             (make-java-array-of "java.lang.String" (mapcar #'jstring strings))))
      (when (context-protocols context)
        (java-call "setProtocols([Ljava/lang/String;)V" params
                   (string-array (context-protocols context))))
      (when (context-cipher-suites context)
        (java-call "setCipherSuites([Ljava/lang/String;)V" params
                   (string-array (context-cipher-suites context))))
      (when (and client hostname (context-check-hostname context))
        (java-call "setEndpointIdentificationAlgorithm(Ljava/lang/String;)V"
                   params (jstring "HTTPS")))
      (let ((alpn-list (or alpn (context-alpn-protocols context))))
        (when alpn-list
          (java-call "setApplicationProtocols([Ljava/lang/String;)V"
                     params (string-array alpn-list))))
      (unless client
        (let ((vm (or verify (context-verify-mode context))))
          (cond
            ((= vm +verify-required+) (java-call "setNeedClientAuth(Z)V" params 1))
            ((= vm +verify-peer+) (java-call "setWantClientAuth(Z)V" params 1))))))
    (java-call "setSSLParameters(Ljavax/net/ssl/SSLParameters;)V" e params)
    e))

;;;; Stream classes

(defclass jsse-stream (trivial-gray-stream-mixin
                       fundamental-binary-input-stream
                       fundamental-binary-output-stream)
  ((engine :initarg :engine :reader stream-engine)
   (underlying :initarg :underlying :reader stream-underlying-stream)
   (context :initarg :context :initform nil :reader stream-context)
   (close-callback :initarg :close-callback :initform nil)
   (closed :initform nil :accessor stream-closed-p))
  (:documentation "A binary TLS gray stream over a caller-provided transport."))

(defclass jsse-client-stream (jsse-stream) ())
(defclass jsse-server-stream (jsse-stream) ())

(defmethod stream-element-type ((stream jsse-stream))
  '(unsigned-byte 8))

;;;; Input

(defmethod stream-read-byte ((stream jsse-stream))
  (if (stream-closed-p stream)
      :eof
      (let ((eng (stream-engine stream)))
        (if (engine-ensure-plaintext eng)
            (let ((pos (tls-engine-plain-pos eng)))
              (prog1 (aref (tls-engine-plain eng) pos)
                (setf (tls-engine-plain-pos eng) (1+ pos))
                (%fifo-reset-if-drained eng)))
            :eof))))

(defmethod stream-read-sequence ((stream jsse-stream) sequence start end &key)
  (if (stream-closed-p stream)
      start
      (let ((eng (stream-engine stream))
            (pos start)
            (first t))
        (loop while (< pos end) do
          (when (%fifo-empty-p eng)
            ;; After the first chunk, don't block waiting for data the peer may
            ;; not send until it has our reply (classic request/response deadlock).
            (when (and (not first) (not (listen (stream-underlying-stream stream))))
              (return-from stream-read-sequence pos))
            (unless (engine-ensure-plaintext eng)
              (return-from stream-read-sequence pos)))
          (let* ((fifo (tls-engine-plain eng))
                 (avail (- (fill-pointer fifo) (tls-engine-plain-pos eng)))
                 (to-copy (min avail (- end pos))))
            (when (zerop to-copy) (return-from stream-read-sequence pos))
            (replace sequence fifo
                     :start1 pos :end1 (+ pos to-copy)
                     :start2 (tls-engine-plain-pos eng))
            (incf pos to-copy)
            (incf (tls-engine-plain-pos eng) to-copy)
            (%fifo-reset-if-drained eng)
            (setf first nil)))
        pos)))

(defmethod stream-listen ((stream jsse-stream))
  (and (not (stream-closed-p stream))
       (or (not (%fifo-empty-p (stream-engine stream)))
           (listen (stream-underlying-stream stream)))))

;;;; Output

(defmethod stream-write-byte ((stream jsse-stream) byte)
  (engine-write (stream-engine stream)
                (make-array 1 :element-type '(unsigned-byte 8) :initial-element byte)
                0 1)
  byte)

(defmethod stream-write-sequence ((stream jsse-stream) sequence start end &key)
  (let ((vector (if (typep sequence '(simple-array (unsigned-byte 8) (*)))
                    sequence
                    (map '(simple-array (unsigned-byte 8) (*))
                         (lambda (b) (logand b #xff))
                         (subseq sequence start end)))))
    (if (eq vector sequence)
        (engine-write (stream-engine stream) vector start end)
        (engine-write (stream-engine stream) vector 0 (length vector))))
  sequence)

(defmethod stream-force-output ((stream jsse-stream))
  (force-output (stream-underlying-stream stream))
  nil)

(defmethod stream-finish-output ((stream jsse-stream))
  (finish-output (stream-underlying-stream stream))
  nil)

;;;; Close

(defmethod close ((stream jsse-stream) &key abort)
  (unless (stream-closed-p stream)
    (setf (stream-closed-p stream) t)
    (unless abort
      (ignore-errors (engine-close (stream-engine stream))))
    (let ((cb (slot-value stream 'close-callback)))
      (when cb (ignore-errors (funcall cb stream))))
    (ignore-errors (close (stream-underlying-stream stream) :abort abort)))
  t)

;;;; Constructors

(defun %default-context ()
  (or *default-context*
      (setf *default-context* (make-context))))

(defun make-client-stream (transport &key context hostname alpn-protocols close-callback)
  "Open a TLS client stream over TRANSPORT (a binary stream).  CONTEXT carries
the trust policy (default: verify against the system CAs); HOSTNAME is the
server name for SNI and verification; ALPN-PROTOCOLS overrides the context's
list.  The handshake runs before this returns."
  (start)
  (let* ((ctx (or context (%default-context)))
         (ssl-engine (%create-ssl-engine ctx :client t :hostname hostname
                                             :alpn alpn-protocols))
         (eng (%make-engine-pump ssl-engine transport)))
    (engine-handshake eng)
    (make-instance 'jsse-client-stream
                   :engine eng :underlying transport
                   :context ctx :close-callback close-callback)))

(defun make-server-stream (transport &key context alpn-protocols verify close-callback)
  "Open a TLS server stream over TRANSPORT (a binary stream).  CONTEXT must
carry the server's identity (a KEYSTORE); VERIFY overrides its client-certificate
policy.  The handshake runs before this returns."
  (start)
  (let* ((ctx (or context *default-context*
                  (error 'jsse-error
                         :message "MAKE-SERVER-STREAM needs a CONTEXT with the server's key store")))
         (ssl-engine (%create-ssl-engine ctx :client nil :alpn alpn-protocols :verify verify))
         (eng (%make-engine-pump ssl-engine transport)))
    (engine-handshake eng)
    (make-instance 'jsse-server-stream
                   :engine eng :underlying transport
                   :context ctx :close-callback close-callback)))

(defmacro with-client-stream ((var transport &rest args) &body body)
  "Bind VAR to a client stream (MAKE-CLIENT-STREAM's ARGS) for BODY, then close it."
  `(let ((,var (make-client-stream ,transport ,@args)))
     (unwind-protect (progn ,@body) (close ,var))))

(defmacro with-server-stream ((var transport &rest args) &body body)
  "Bind VAR to a server stream (MAKE-SERVER-STREAM's ARGS) for BODY, then close it."
  `(let ((,var (make-server-stream ,transport ,@args)))
     (unwind-protect (progn ,@body) (close ,var))))

;;;; Stream accessors

(defmethod peer-certificate ((stream jsse-stream))
  "The peer's leaf (end-entity) certificate, or NIL if it presented none."
  (first (engine-peer-certificates (stream-engine stream))))

(defmethod peer-certificate-chain ((stream jsse-stream))
  "The peer's certificate chain, leaf first, or NIL."
  (engine-peer-certificates (stream-engine stream)))

(defmethod selected-alpn ((stream jsse-stream))
  "The negotiated ALPN protocol name, or NIL."
  (engine-selected-alpn (stream-engine stream)))

(defmethod cipher-suite ((stream jsse-stream))
  "The negotiated cipher suite name."
  (engine-cipher-suite (stream-engine stream)))

(defmethod protocol-version ((stream jsse-stream))
  "The negotiated protocol version name (e.g. \"TLSv1.3\")."
  (engine-protocol (stream-engine stream)))

(defmethod client-hostname ((stream jsse-server-stream))
  "The SNI hostname the client requested, or NIL.  (Server streams only.)"
  nil)
