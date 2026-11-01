;;;; engine.lisp --- Driving javax.net.ssl.SSLEngine over a Lisp byte stream.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; SSLEngine is JSSE's transport-agnostic TLS state machine: you hand it
;;;; ciphertext with unwrap() and plaintext with wrap(), and it never touches
;;;; the network itself.  That is exactly what lets cl-jsse wrap a
;;;; caller-provided Lisp byte stream.  This file is the pump that shuttles
;;;; bytes between that stream and the engine; streams.lisp puts a gray stream
;;;; on top.
;;;;
;;;; Transport reads are framed by the TLS record header (content type, 2-byte
;;;; version, 2-byte length): we read exactly one complete record at a time.
;;;; That keeps a blocking transport from deadlocking (we never wait for more
;;;; bytes than the peer has promised) and keeps the count of unwrap() calls --
;;;; each an interpreted Java round-trip under OpenLDK, and so not free -- down
;;;; to roughly one per record.

(in-package #:cl-jsse)

;;;; ByteBuffer helpers.  ByteBuffer's position/limit/flip/clear/compact
;;;; overrides return ByteBuffer (covariant, JDK 9+), so we use ByteBuffer
;;;; descriptors throughout.

(defun bb-allocate (n)
  (java-static "java.nio.ByteBuffer" "allocate(I)Ljava/nio/ByteBuffer;" n))
(defun bb-flip (b) (java-call "flip()Ljava/nio/ByteBuffer;" b))
(defun bb-clear (b) (java-call "clear()Ljava/nio/ByteBuffer;" b))
(defun bb-compact (b) (java-call "compact()Ljava/nio/ByteBuffer;" b))
(defun bb-has-remaining (b) (eql 1 (java-call "hasRemaining()Z" b)))
(defun bb-remaining (b) (java-call "remaining()I" b))
(defun bb-position (b) (java-call "position()I" b))
(defun bb-capacity (b) (java-call "capacity()I" b))

;;;; SSLEngineResult / status helpers (statuses compared by their enum name).

(defun %enum-name (enum) (lstring (java-call "name()Ljava/lang/String;" enum)))
(defun result-status (r)
  (%enum-name (java-call "getStatus()Ljavax/net/ssl/SSLEngineResult$Status;" r)))
(defun result-hstatus (r)
  (%enum-name (java-call "getHandshakeStatus()Ljavax/net/ssl/SSLEngineResult$HandshakeStatus;" r)))
(defun engine-hstatus (e)
  (%enum-name (java-call "getHandshakeStatus()Ljavax/net/ssl/SSLEngineResult$HandshakeStatus;" e)))

(defun run-delegated-tasks (e)
  "Run every delegated task the engine has queued (key derivation, cert
validation -- work JSSE farms out of wrap/unwrap)."
  (loop for task = (java-call "getDelegatedTask()Ljava/lang/Runnable;" e)
        while task do (java-call "run()V" task)))

(defun %wrap (e src dst)
  (java-call "wrap(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;" e src dst))
(defun %unwrap (e src dst)
  (java-call "unwrap(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;" e src dst))

;;;; Lisp <-> Java byte bridging.  Java bytes are signed.

(declaim (inline %u8->s8 %s8->u8))
(defun %u8->s8 (b) (if (>= b 128) (- b 256) b))
(defun %s8->u8 (b) (logand b #xff))

(defun %lisp->jbytes (vector start end)
  "A Java byte[] holding VECTOR[START:END] (unsigned bytes)."
  (make-java-array-of "byte"
                      (loop for i from start below end collect (%u8->s8 (aref vector i)))))

(defun %jbyte-array (n)
  "A fresh zero-filled Java byte[N] to read into."
  (make-java-array-of "byte" (make-array n :element-type '(signed-byte 8) :initial-element 0)))

(defun %jbytes->lisp (jarr n)
  "The first N bytes of Java byte[] JARR, as an (unsigned-byte 8) vector."
  (let ((out (make-array n :element-type '(unsigned-byte 8))))
    (loop for i from 0 below n
          for b in (java-array-list jarr)
          do (setf (aref out i) (%s8->u8 b)))
    out))

;;;; The engine pump

(defstruct (tls-engine (:constructor %make-tls-engine))
  engine                 ; the Java javax.net.ssl.SSLEngine
  transport              ; the caller's (unsigned-byte 8) stream
  net-in                 ; ByteBuffer, write mode: ciphertext read from TRANSPORT
  net-out                ; ByteBuffer scratch for wrap() output
  app-scratch            ; ByteBuffer scratch for unwrap() output
  plain                  ; decrypted plaintext FIFO (adjustable, fill-pointer)
  (plain-pos 0)          ; read index into PLAIN
  empty                  ; a 0-length ByteBuffer, the wrap() source during handshakes
  handshake-done
  inbound-closed
  outbound-closed)

(defun %make-engine-pump (ssl-engine transport)
  (let* ((session (java-call "getSession()Ljavax/net/ssl/SSLSession;" ssl-engine))
         (packet (java-call "getPacketBufferSize()I" session))
         (app (java-call "getApplicationBufferSize()I" session)))
    (%make-tls-engine
     :engine ssl-engine
     :transport transport
     :net-in (bb-allocate (max packet 18432))
     :net-out (bb-allocate (max packet 18432))
     :app-scratch (bb-allocate (max app 18432))
     :empty (bb-allocate 0)
     :plain (make-array 4096 :element-type '(unsigned-byte 8)
                             :adjustable t :fill-pointer 0))))

;;;; Transport I/O, framed by the TLS record header

(defun %read-exactly (stream n)
  "Read exactly N bytes from STREAM into a fresh vector, or :EOF if the stream
ends before N bytes arrive."
  (let* ((buf (make-array n :element-type '(unsigned-byte 8)))
         (got (read-sequence buf stream)))
    (if (< got n) :eof buf)))

(defun %put-bytes (bb vector n)
  "Append VECTOR[0:N] to BB (write mode)."
  (java-call "put([BII)Ljava/nio/ByteBuffer;" bb (%lisp->jbytes vector 0 n) 0 n))

(defun %fill-one-record (eng)
  "Read exactly one TLS record from the transport into NET-IN (write mode).
Returns T, or :EOF at end of stream."
  (let ((hdr (%read-exactly (tls-engine-transport eng) 5)))
    (if (eq hdr :eof)
        :eof
        (let ((len (+ (ash (aref hdr 3) 8) (aref hdr 4))))
          (%put-bytes (tls-engine-net-in eng) hdr 5)
          (when (plusp len)
            (let ((body (%read-exactly (tls-engine-transport eng) len)))
              (when (eq body :eof) (return-from %fill-one-record :eof))
              (%put-bytes (tls-engine-net-in eng) body len)))
          t))))

(defun %drain-net-out (eng)
  "Write all ciphertext now in NET-OUT to the transport and flush it."
  (let ((nb (tls-engine-net-out eng)))
    (bb-flip nb)
    (let ((n (bb-remaining nb)))
      (when (plusp n)
        (let ((jarr (%jbyte-array n)))
          (java-call "get([B)Ljava/nio/ByteBuffer;" nb jarr)
          (write-sequence (%jbytes->lisp jarr n) (tls-engine-transport eng))
          (force-output (tls-engine-transport eng)))))
    (bb-clear nb)))

;;;; Growing scratch buffers when the engine asks (BUFFER_OVERFLOW)

(defun %grow-app-scratch (eng)
  (let* ((session (java-call "getSession()Ljavax/net/ssl/SSLSession;" (tls-engine-engine eng)))
         (want (java-call "getApplicationBufferSize()I" session))
         (now (bb-capacity (tls-engine-app-scratch eng))))
    (setf (tls-engine-app-scratch eng) (bb-allocate (max want (* 2 now))))))

(defun %grow-net-out (eng)
  (let* ((session (java-call "getSession()Ljavax/net/ssl/SSLSession;" (tls-engine-engine eng)))
         (want (java-call "getPacketBufferSize()I" session))
         (now (bb-capacity (tls-engine-net-out eng))))
    (setf (tls-engine-net-out eng) (bb-allocate (max want (* 2 now))))))

;;;; Plaintext FIFO

(defun %fifo-empty-p (eng)
  (>= (tls-engine-plain-pos eng) (fill-pointer (tls-engine-plain eng))))

(defun %fifo-push (eng app)
  "Flip APP (unwrap output, write mode) and append its bytes to the FIFO."
  (bb-flip app)
  (let ((n (bb-remaining app)))
    (when (plusp n)
      (let ((jarr (%jbyte-array n))
            (fifo (tls-engine-plain eng)))
        (java-call "get([B)Ljava/nio/ByteBuffer;" app jarr)
        (loop for b across (%jbytes->lisp jarr n) do (vector-push-extend b fifo)))))
  (bb-clear app))

(defun %fifo-reset-if-drained (eng)
  (when (%fifo-empty-p eng)
    (setf (fill-pointer (tls-engine-plain eng)) 0
          (tls-engine-plain-pos eng) 0)))

;;;; Handshake servicing: run tasks and emit any wrap() output the engine owes.
;;;; This drives the NEED_TASK and NEED_WRAP transitions; the caller drives
;;;; NEED_UNWRAP by reading records.  Used both during the initial handshake
;;;; and for post-handshake messages (TLS 1.3 KeyUpdate, NewSessionTicket).

(defun %service-output (eng)
  "Emit wrap() output while the engine needs it.  Returns the handshake status
left once it no longer needs to wrap (NEED_UNWRAP, FINISHED, NOT_HANDSHAKING)."
  (let ((e (tls-engine-engine eng)))
    (loop
      (let ((hs (engine-hstatus e)))
        (cond
          ((string= hs "NEED_TASK") (run-delegated-tasks e))
          ((string= hs "NEED_WRAP")
           (let ((r (%wrap e (tls-engine-empty eng) (tls-engine-net-out eng))))
             (%drain-net-out eng)
             (let ((status (result-status r)))
               (cond
                 ((string= status "BUFFER_OVERFLOW") (%grow-net-out eng))
                 ((string= status "CLOSED")
                  (setf (tls-engine-outbound-closed eng) t)
                  (return hs))))))
          (t (return hs)))))))

(defun %unwrap-step (eng)
  "Feed the engine one record's worth of ciphertext and unwrap it, appending any
plaintext to the FIFO.  Returns the SSLEngineResult, or NIL at clean EOF."
  (let ((e (tls-engine-engine eng))
        (nin (tls-engine-net-in eng))
        (app (tls-engine-app-scratch eng)))
    (when (zerop (bb-position nin))
      (when (eq (%fill-one-record eng) :eof)
        (setf (tls-engine-inbound-closed eng) t)
        (return-from %unwrap-step nil)))
    (loop
      (bb-flip nin)
      (let* ((r (%unwrap e nin app))
             (status (result-status r)))
        (bb-compact nin)
        (cond
          ((string= status "BUFFER_OVERFLOW") (%grow-app-scratch eng))
          ((string= status "BUFFER_UNDERFLOW")
           (when (eq (%fill-one-record eng) :eof)
             (setf (tls-engine-inbound-closed eng) t)
             (return r)))
          (t
           (%fifo-push eng app)
           (when (string= status "CLOSED")
             (setf (tls-engine-inbound-closed eng) t))
           (return r)))))))

(defun engine-handshake (eng)
  "Run the TLS handshake to completion."
  (let ((e (tls-engine-engine eng)))
    (with-foreign-errors ("JSSE")
      (java-call "beginHandshake()V" e)
      (loop
        (let ((hs (%service-output eng)))
          (cond
            ((or (string= hs "FINISHED") (string= hs "NOT_HANDSHAKING"))
             (setf (tls-engine-handshake-done eng) t)
             (return))
            ((or (string= hs "NEED_UNWRAP") (string= hs "NEED_UNWRAP_AGAIN"))
             (let ((r (%unwrap-step eng)))
               (when (null r)
                 (error 'jsse-handshake-error
                        :message "transport closed during TLS handshake"))))
            (t (error 'jsse-handshake-error
                      :message (format nil "unexpected handshake status ~A" hs)))))))
    (setf (tls-engine-handshake-done eng) t)))

;;;; Application data

(defun engine-ensure-plaintext (eng)
  "Ensure the FIFO holds unread plaintext, unwrapping records until some arrives
or the peer closes.  Returns T if plaintext is available, NIL at EOF."
  (loop
    (unless (%fifo-empty-p eng) (return t))
    (when (tls-engine-inbound-closed eng) (return nil))
    (with-foreign-errors ("JSSE")
      (let ((r (%unwrap-step eng)))
        ;; A record may carry a post-handshake message the engine must answer.
        (%service-output eng)
        (when (and (null r) (%fifo-empty-p eng)) (return nil))))))

(defun engine-write (eng vector start end)
  "Encrypt VECTOR[START:END] and write the ciphertext to the transport."
  (when (tls-engine-outbound-closed eng)
    (error 'jsse-error :message "write on a closed TLS stream"))
  (with-foreign-errors ("JSSE")
    (let ((e (tls-engine-engine eng))
          (src (java-static "java.nio.ByteBuffer" "wrap([B)Ljava/nio/ByteBuffer;"
                            (%lisp->jbytes vector start end))))
      (loop while (bb-has-remaining src)
            do (let* ((r (%wrap e src (tls-engine-net-out eng)))
                      (status (result-status r)))
                 (%drain-net-out eng)
                 (cond
                   ((string= status "BUFFER_OVERFLOW") (%grow-net-out eng))
                   ((string= status "CLOSED")
                    (setf (tls-engine-outbound-closed eng) t)
                    (error 'jsse-error :message "write on a closed TLS stream"))))))))

(defun engine-close (eng)
  "Send close_notify and mark the engine's outbound side done.  Leaves the
transport itself for the caller to close."
  (unless (tls-engine-outbound-closed eng)
    (with-foreign-errors ("JSSE")
      (let ((e (tls-engine-engine eng)))
        (java-call "closeOutbound()V" e)
        (loop until (eql 1 (java-call "isOutboundDone()Z" e))
              do (let ((r (%wrap e (tls-engine-empty eng) (tls-engine-net-out eng))))
                   (%drain-net-out eng)
                   (when (string= (result-status r) "CLOSED") (return))))))
    (setf (tls-engine-outbound-closed eng) t)))

;;;; Session accessors (read after the handshake)

(defun engine-session (eng)
  (java-call "getSession()Ljavax/net/ssl/SSLSession;" (tls-engine-engine eng)))

(defun engine-protocol (eng)
  (lstring (java-call "getProtocol()Ljava/lang/String;" (engine-session eng))))

(defun engine-cipher-suite (eng)
  (lstring (java-call "getCipherSuite()Ljava/lang/String;" (engine-session eng))))

(defun engine-peer-certificates (eng)
  "The peer's certificate chain as a list of java.security.cert.Certificate,
or NIL if the peer presented none."
  (handler-case
      (java-array-list
       (java-call "getPeerCertificates()[Ljava/security/cert/Certificate;" (engine-session eng)))
    (foreign-error () nil)))

(defun engine-selected-alpn (eng)
  (let ((s (java-call "getApplicationProtocol()Ljava/lang/String;" (tls-engine-engine eng))))
    (let ((str (and s (lstring s))))
      (if (and str (plusp (length str))) str nil))))
