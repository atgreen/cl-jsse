;;;; context.lisp --- SSLContext construction: key and trust material.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A CONTEXT wraps a configured javax.net.ssl.SSLContext together with the
;;;; policy cl-jsse applies around it (verification mode, ALPN, hostname
;;;; checking).  The SSLContext carries the KeyManagers (our own identity: a
;;;; server's certificate+key, or a client cert for mTLS) and TrustManagers
;;;; (whom we trust: the system CAs, a supplied trust store, or -- for
;;;; +verify-none+ -- a trust-all manager).

(in-package #:cl-jsse)

(defconstant +verify-none+ 0
  "Do not verify the peer's certificate at all.")
(defconstant +verify-peer+ 1
  "Verify the peer's certificate if one is presented, but tolerate its absence.")
(defconstant +verify-required+ 2
  "Require the peer to present a certificate and verify it.")

(defstruct (context (:constructor %make-context))
  "A configured javax.net.ssl.SSLContext and the policy cl-jsse layers on it."
  ssl-context                       ; the Java javax.net.ssl.SSLContext
  (verify-mode +verify-required+)
  alpn-protocols                    ; list of protocol-name strings, most-preferred first
  protocols                         ; enabled TLS versions, e.g. ("TLSv1.3" "TLSv1.2"); NIL = JDK default
  cipher-suites                     ; enabled cipher-suite names; NIL = JDK default
  (check-hostname t))               ; endpoint identification (clients)

(defvar *default-context* nil
  "The context used when a stream constructor is given none.")

;;; Trust-all manager
;;;
;;; An X509TrustManager implemented in Lisp whose checks accept everything, for
;;; +verify-none+.  DEFINE-JAVA-CLASS starts the runtime and installs CLOS
;;; methods via EVAL, so it must not run at load time; ENSURE-TRUST-ALL defines
;;; it on first use and memoises that.

(defvar *trust-all-defined* nil)

(defun ensure-trust-all ()
  "Define the trust-all X509TrustManager class, once, and return its name."
  (unless *trust-all-defined*
    (define-java-class trust-all (:implements ("javax.net.ssl.X509TrustManager")) ()
      ("checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" (self chain at) nil)
      ("checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V" (self chain at) nil)
      ("getAcceptedIssuers()[Ljava/security/cert/X509Certificate;" (self)
       (make-java-array-of "java.security.cert.X509Certificate" '())))
    (setf *trust-all-defined* t))
  'trust-all)

;;; Key and trust material

(defun %load-keystore (path password type)
  "A java.security.KeyStore of TYPE loaded from the file at PATH, unlocked with
PASSWORD (a string or NIL).  Returns (values keystore password-char-array)."
  (let* ((ks (java-static "java.security.KeyStore"
                          "getInstance(Ljava/lang/String;)Ljava/security/KeyStore;"
                          (jstring type)))
         (fis (java-new "java.io.FileInputStream" "(Ljava/lang/String;)V"
                        (jstring (namestring (truename path)))))
         (pwc (and password (java-call "toCharArray()[C" (jstring password)))))
    (java-call "load(Ljava/io/InputStream;[C)V" ks fis pwc)
    (java-call "close()V" fis)
    (values ks pwc)))

(defun %key-managers (keystore keystore-password keystore-type)
  "The KeyManager[] for our own identity, from the key store at KEYSTORE."
  (multiple-value-bind (ks pwc) (%load-keystore keystore keystore-password keystore-type)
    (let* ((alg (java-static "javax.net.ssl.KeyManagerFactory"
                             "getDefaultAlgorithm()Ljava/lang/String;"))
           (kmf (java-static "javax.net.ssl.KeyManagerFactory"
                             "getInstance(Ljava/lang/String;)Ljavax/net/ssl/KeyManagerFactory;"
                             alg)))
      (java-call "init(Ljava/security/KeyStore;[C)V" kmf ks pwc)
      (java-call "getKeyManagers()[Ljavax/net/ssl/KeyManager;" kmf))))

(defun %trust-managers (verify-mode truststore truststore-password truststore-type)
  "The TrustManager[] implementing VERIFY-MODE.  +verify-none+ yields a
trust-all manager; otherwise the managers come from TRUSTSTORE, or the JDK's
default trust store (system CAs) when no TRUSTSTORE is given."
  (if (= verify-mode +verify-none+)
      (make-java-array-of "javax.net.ssl.TrustManager"
                          (list (make-java-object (ensure-trust-all))))
      (let* ((alg (java-static "javax.net.ssl.TrustManagerFactory"
                               "getDefaultAlgorithm()Ljava/lang/String;"))
             (tmf (java-static "javax.net.ssl.TrustManagerFactory"
                               "getInstance(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;"
                               alg))
             (ks (when truststore
                   (%load-keystore truststore truststore-password truststore-type))))
        ;; init with NIL key store loads the JDK default (system CA) trust store.
        (java-call "init(Ljava/security/KeyStore;)V" tmf ks)
        (java-call "getTrustManagers()[Ljavax/net/ssl/TrustManager;" tmf))))

(defun make-context (&key (verify-mode +verify-required+)
                          keystore keystore-password (keystore-type "PKCS12")
                          truststore truststore-password (truststore-type "PKCS12")
                          alpn-protocols protocols cipher-suites (check-hostname t))
  "Build a CONTEXT around a fresh TLS javax.net.ssl.SSLContext.

   VERIFY-MODE is +verify-none+, +verify-peer+, or +verify-required+.

   KEYSTORE / KEYSTORE-PASSWORD / KEYSTORE-TYPE give our own identity: a server
   needs this (its certificate chain and private key); a client needs it only
   for mTLS.  The store defaults to PKCS12.

   TRUSTSTORE / TRUSTSTORE-PASSWORD / TRUSTSTORE-TYPE name a key store of CA
   certificates to trust; without it, verification uses the JDK's system CAs.

   ALPN-PROTOCOLS is a list of protocol-name strings to negotiate.
   PROTOCOLS restricts the enabled TLS versions (e.g. '(\"TLSv1.2\")); CIPHER-SUITES
   restricts the enabled cipher suites.  Both default to the JDK's own defaults.
   CHECK-HOSTNAME turns on endpoint identification for client streams."
  (start)
  (with-foreign-errors ("JSSE")
    (let* ((ctx (java-static "javax.net.ssl.SSLContext"
                             "getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;"
                             (jstring "TLS")))
           (kms (when keystore
                  (%key-managers keystore keystore-password keystore-type)))
           (tms (%trust-managers verify-mode truststore truststore-password truststore-type)))
      (java-call "init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V"
                 ctx kms tms nil)
      (%make-context :ssl-context ctx
                     :verify-mode verify-mode
                     :alpn-protocols alpn-protocols
                     :protocols protocols
                     :cipher-suites cipher-suites
                     :check-hostname check-hostname))))

(defun context-free (context)
  "Release CONTEXT.  JSSE objects are garbage-collected, so this only drops the
Lisp reference; it exists for API parity with cl+ssl/pure-tls."
  (when (context-p context)
    (setf (context-ssl-context context) nil))
  nil)

(defmacro with-context ((var &rest options) &body body)
  "Bind VAR to a fresh context (MAKE-CONTEXT's OPTIONS) for BODY, then free it."
  `(let ((,var (make-context ,@options)))
     (unwind-protect (progn ,@body)
       (context-free ,var))))
