;;;; Spike: does javax.net.ssl.SSLEngine work under OpenLDK?
;;;;
;;;; This is the core unknown for cl-jsse: the library wraps a caller-provided
;;;; Lisp byte stream, so it must drive TLS with SSLEngine (the transport-
;;;; agnostic wrap/unwrap API), not SSLSocket.  Here we run a client engine and
;;;; a server engine in-process, shuttling each wrap() output into the other's
;;;; unwrap(), until the handshake completes -- then push one application
;;;; record through.  No sockets, so it tests the engine + crypto alone.
;;;;
;;;; Server identity comes from spikes/server.p12 -- not committed; create it
;;;; first with `sh spikes/gen-test-keystore.sh`.  The client uses a trust-all
;;;; X509TrustManager implemented in Lisp,
;;;; to isolate the engine from OpenLDK's known cert-path/IDN gaps.

(require :asdf)
(asdf:load-system "openldk/interop")

(defpackage :jsse-spike (:use :cl :openldk.interop))
(in-package :jsse-spike)

(start-runtime)

(defun jstr (s) (openldk::jstring s))
(defun lstr (j) (and j (openldk::lstring j)))
(defun allocate (n) (java-static "java.nio.ByteBuffer" "allocate(I)Ljava/nio/ByteBuffer;" n))
(defun flip (b) (java-call "flip()Ljava/nio/ByteBuffer;" b))
(defun has-remaining (b) (eql 1 (java-call "hasRemaining()Z" b)))
(defun hstatus (e)
  (lstr (java-call "name()Ljava/lang/String;"
                   (java-call "getHandshakeStatus()Ljavax/net/ssl/SSLEngineResult$HandshakeStatus;" e))))
(defun run-tasks (e)
  (loop for task = (java-call "getDelegatedTask()Ljava/lang/Runnable;" e)
        while task do (java-call "run()V" task)))

;; Trust-all X509TrustManager, implemented in Lisp.
(define-java-class trust-all (:implements ("javax.net.ssl.X509TrustManager")) ()
  ("checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" (self chain at) nil)
  ("checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" (self chain at) nil)
  ("getAcceptedIssuers()[Ljava/security/cert/X509Certificate;" (self)
   (openldk::make-java-array :size 0 :component-class (java-load "java.security.cert.X509Certificate"))))

(defun server-context (p12 pass)
  (let* ((ks (java-static "java.security.KeyStore" "getInstance(Ljava/lang/String;)Ljava/security/KeyStore;" (jstr "PKCS12")))
         (fis (java-new "java.io.FileInputStream" "(Ljava/lang/String;)V" (jstr p12)))
         (pwc (java-call "toCharArray()[C" (jstr pass))))
    (java-call "load(Ljava/io/InputStream;[C)V" ks fis pwc)
    (let* ((alg (java-static "javax.net.ssl.KeyManagerFactory" "getDefaultAlgorithm()Ljava/lang/String;"))
           (kmf (java-static "javax.net.ssl.KeyManagerFactory" "getInstance(Ljava/lang/String;)Ljavax/net/ssl/KeyManagerFactory;" alg))
           (ctx (java-static "javax.net.ssl.SSLContext" "getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;" (jstr "TLS"))))
      (java-call "init(Ljava/security/KeyStore;[C)V" kmf ks pwc)
      (java-call "init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V"
                 ctx (java-call "getKeyManagers()[Ljavax/net/ssl/KeyManager;" kmf) nil nil)
      ctx)))

(defun client-context ()
  (let* ((tm (make-java-object 'trust-all))
         (tms (openldk::make-java-array :size 1 :component-class (java-load "javax.net.ssl.TrustManager")))
         (ctx (java-static "javax.net.ssl.SSLContext" "getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;" (jstr "TLS"))))
    (setf (aref (openldk::java-array-data tms) 0) tm)
    (java-call "init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V" ctx nil tms nil)
    ctx))

(defun make-engine (ctx client-p)
  (let ((e (java-call "createSSLEngine()Ljavax/net/ssl/SSLEngine;" ctx)))
    (java-call "setUseClientMode(Z)V" e (if client-p 1 0))
    e))

(defun wrapp (e src dst) (java-call "wrap(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;" e src dst))
(defun unwrapp (e src dst) (java-call "unwrap(Ljava/nio/ByteBuffer;Ljava/nio/ByteBuffer;)Ljavax/net/ssl/SSLEngineResult;" e src dst))
(defun done-p (e) (string= (hstatus e) "NOT_HANDSHAKING"))

(defun drive (client server)
  (java-call "beginHandshake()V" client)
  (java-call "beginHandshake()V" server)
  (let ((empty (flip (allocate 1024))))
    (dotimes (i 200 (error "handshake did not converge"))
      (when (and (done-p client) (done-p server)) (return))
      (dolist (pair (list (cons client server) (cons server client)))
        (let ((src (car pair)) (dst (cdr pair)))
          (run-tasks src)
          (when (string= (hstatus src) "NEED_WRAP")
            (let ((net (allocate 32768)) (app (allocate 32768)))
              (wrapp src empty net)
              (flip net)
              (run-tasks src)
              (loop while (has-remaining net)
                    do (unwrapp dst net app) (run-tasks dst)))))))))

(defun session-line (label e)
  (let ((s (java-call "getSession()Ljavax/net/ssl/SSLSession;" e)))
    (format t "  ~A: protocol=~A cipher=~A~%" label
            (lstr (java-call "getProtocol()Ljava/lang/String;" s))
            (lstr (java-call "getCipherSuite()Ljava/lang/String;" s)))))

(defun app-exchange (client server text)
  (let* ((bytes (openldk::make-java-array :component-class (java-load "byte") :element-type '(signed-byte 8)
                                          :initial-contents (map 'list #'char-code text)))
         (src (java-static "java.nio.ByteBuffer" "wrap([B)Ljava/nio/ByteBuffer;" bytes))
         (net (allocate 32768)) (app (allocate 32768)))
    (wrapp client src net)
    (flip net)
    (loop while (has-remaining net) do (unwrapp server net app))
    (flip app)
    (let* ((n (java-call "remaining()I" app))
           (buf (openldk::make-java-array :size n :component-class (java-load "byte") :element-type '(signed-byte 8))))
      (java-call "get([B)Ljava/nio/ByteBuffer;" app buf)
      (lstr (java-new "java.lang.String" "([BLjava/lang/String;)V" buf (jstr "UTF-8"))))))

(handler-case
    (let* ((p12 (namestring (merge-pathnames "server.p12" #.(or *load-truename* ""))))
           (sctx (server-context p12 "changeit"))
           (cctx (client-context))
           (client (make-engine cctx t))
           (server (make-engine sctx nil)))
      (format t "~%driving handshake...~%")
      (drive client server)
      (format t "handshake COMPLETE~%")
      (session-line "client" client)
      (session-line "server" server)
      (let ((got (app-exchange client server "PING-JSSE")))
        (format t "  app data client->server: ~S~%" got)
        (format t "~%SPIKE ~A~%" (if (string= got "PING-JSSE") "PASS" "FAIL (data mismatch)"))))
  (error (e) (format t "~%SPIKE FAILED: ~A~%" (let ((s (princ-to-string e))) (subseq s 0 (min 300 (length s)))))))
