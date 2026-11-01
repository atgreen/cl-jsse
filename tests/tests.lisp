;;;; tests.lisp --- Integration tests for cl-jsse.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; A real client<->server TLS exchange over a loopback TCP socket, driven by
;;;; the gray-stream API.  Forced to TLS 1.2 with RSA key exchange: OpenLDK
;;;; interprets the crypto, and the default TLS 1.3 ECDHE suites are too slow to
;;;; test against.  The server identity is a throwaway self-signed PKCS12
;;;; generated here at test time with the JDK's keytool (so no private key is
;;;; committed); the client uses +verify-none+ with hostname checking off, since
;;;; the point here is the plumbing, not the trust decision.

(defpackage #:cl-jsse/tests
  (:use #:cl #:fiveam))

(in-package #:cl-jsse/tests)

(def-suite cl-jsse :description "cl-jsse integration tests")
(in-suite cl-jsse)

(defparameter *keystore-password* "changeit")
(defparameter *fast-protocols* '("TLSv1.2"))
(defparameter *fast-ciphers* '("TLS_RSA_WITH_AES_128_GCM_SHA256"))

(defun %keytool ()
  "Path to the JDK's keytool (via JAVA_HOME), or NIL if it can't be found."
  (let ((home (uiop:getenv "JAVA_HOME")))
    (when home
      (let ((kt (merge-pathnames "bin/keytool" (uiop:ensure-directory-pathname home))))
        (and (probe-file kt) kt)))))

(defun generate-keystore ()
  "Generate a fresh self-signed RSA PKCS12 keystore in a temporary file and
return its pathname, or NIL if keytool is unavailable."
  (let ((keytool (%keytool)))
    (when keytool
      (let ((path (make-pathname
                   :defaults (uiop:temporary-directory)
                   :name (format nil "cl-jsse-test-~36R" (random (expt 36 10) (make-random-state t)))
                   :type "p12")))
        (when (probe-file path) (delete-file path))
        (uiop:run-program
         (list (namestring keytool)
               "-genkeypair" "-alias" "server" "-keyalg" "RSA" "-keysize" "2048"
               "-validity" "1" "-dname" "CN=localhost"
               "-keystore" (namestring path) "-storetype" "PKCS12"
               "-storepass" *keystore-password* "-keypass" *keystore-password*)
         :output :string :error-output :string)
        path))))

(defmacro with-test-keystore ((var) &body body)
  "Bind VAR to a freshly generated keystore for BODY, deleting it afterwards;
skip the test if no keystore can be generated (keytool missing)."
  `(let ((,var (ignore-errors (generate-keystore))))
     (if (not ,var)
         (skip "could not generate a test keystore (need keytool from JAVA_HOME)")
         (unwind-protect (progn ,@body)
           (ignore-errors (delete-file ,var))))))

(defun put-string (stream string)
  "Write STRING's bytes to STREAM and flush."
  (write-sequence (map '(vector (unsigned-byte 8)) #'char-code string) stream)
  (force-output stream))

(defun get-string (stream n)
  "Read exactly N bytes from STREAM and return them as a string."
  (let ((buf (make-array n :element-type '(unsigned-byte 8))))
    (let ((got (read-sequence buf stream)))
      (map 'string #'code-char (subseq buf 0 got)))))

(defun server-context (keystore)
  (cl-jsse:make-context :keystore (namestring keystore)
                        :keystore-password *keystore-password*
                        :verify-mode cl-jsse:+verify-none+
                        :protocols *fast-protocols*
                        :cipher-suites *fast-ciphers*))

(defun client-context ()
  (cl-jsse:make-context :verify-mode cl-jsse:+verify-none+
                        :check-hostname nil
                        :protocols *fast-protocols*
                        :cipher-suites *fast-ciphers*))

(test loopback-echo
  "A client sends a line through TLS; the server echoes it back."
  (with-test-keystore (keystore)
  (cl-jsse:start)   ; bring the runtime up once, before the threads race on it
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)
                                          :reuseaddress t))
         (port (usocket:get-local-port listener))
         (server-error nil)
         (server-got nil)
         (server-thread
           (bt:make-thread
            (lambda ()
              (handler-case
                  (let ((conn (usocket:socket-accept listener
                                                     :element-type '(unsigned-byte 8))))
                    (unwind-protect
                         (cl-jsse:with-server-stream
                             (s (usocket:socket-stream conn) :context (server-context keystore))
                           (let ((line (get-string s 9)))
                             (setf server-got line)
                             (put-string s line)))
                      (ignore-errors (usocket:socket-close conn))))
                (error (e) (setf server-error e))))
            :name "cl-jsse-test-server")))
    (unwind-protect
         (let ((client (usocket:socket-connect "127.0.0.1" port
                                               :element-type '(unsigned-byte 8))))
           (unwind-protect
                (cl-jsse:with-client-stream
                    (s (usocket:socket-stream client) :hostname "localhost"
                                                      :context (client-context))
                  (put-string s "PING-JSSE")
                  (let ((echo (get-string s 9)))
                    (bt:join-thread server-thread)
                    (when server-error (error "server thread failed: ~A" server-error))
                    (is (string= "PING-JSSE" server-got)
                        "server received the plaintext")
                    (is (string= "PING-JSSE" echo)
                        "client received the echo")
                    (is (string= "TLSv1.2" (cl-jsse:protocol-version s))
                        "negotiated TLS 1.2 (got ~S, cipher ~S)"
                        (cl-jsse:protocol-version s) (cl-jsse:cipher-suite s))))
             (ignore-errors (usocket:socket-close client))))
      (ignore-errors (usocket:socket-close listener))))))

;;;; cl+ssl drop-in

(test cl+ssl-loopback-echo
  "The same echo exchange, driven entirely through the CL+SSL drop-in API."
  (with-test-keystore (keystore)
  (cl-jsse:start)   ; bring the runtime up once, before the threads race on it
  (cl+ssl:ensure-initialized)
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0
                                          :element-type '(unsigned-byte 8)
                                          :reuseaddress t))
         (port (usocket:get-local-port listener))
         (server-error nil)
         (server-thread
           (bt:make-thread
            (lambda ()
              (handler-case
                  (let ((conn (usocket:socket-accept listener
                                                     :element-type '(unsigned-byte 8))))
                    (unwind-protect
                         (cl+ssl:with-global-context
                             ((cl+ssl:make-context
                               :keystore (namestring keystore)
                               :keystore-password *keystore-password*
                               :verify-mode cl+ssl:+ssl-verify-none+
                               :protocols *fast-protocols* :cipher-suites *fast-ciphers*))
                           (let ((s (cl+ssl:make-ssl-server-stream
                                     (usocket:socket-stream conn))))
                             (unwind-protect (put-string s (get-string s 9))
                               (close s))))
                      (ignore-errors (usocket:socket-close conn))))
                (error (e) (setf server-error e))))
            :name "cl-jsse-cl+ssl-test-server")))
    (unwind-protect
         (let ((client (usocket:socket-connect "127.0.0.1" port
                                               :element-type '(unsigned-byte 8))))
           (unwind-protect
                (cl+ssl:with-global-context
                    ((cl+ssl:make-context :verify-mode cl+ssl:+ssl-verify-none+
                                          :protocols *fast-protocols*
                                          :cipher-suites *fast-ciphers*))
                  (let ((s (cl+ssl:make-ssl-client-stream (usocket:socket-stream client)
                                                          :hostname "localhost" :verify nil)))
                    (unwind-protect
                         (progn
                           (put-string s "PING-JSSE")
                           (let ((echo (get-string s 9)))
                             (bt:join-thread server-thread)
                             (when server-error (error "server thread failed: ~A" server-error))
                             (is (string= "PING-JSSE" echo)
                                 "CL+SSL client received the echo")))
                      (close s))))
             (ignore-errors (usocket:socket-close client))))
      (ignore-errors (usocket:socket-close listener))))))

;;;; "Refuse, don't silently weaken" behaviour (no handshake; fast)

(test cl+ssl-refuses-verify-callback
  "A :VERIFY-CALLBACK can't be honoured over JSSE, so it is an error, not a no-op."
  (signals cl+ssl:ssl-error
    (cl+ssl:make-context :verify-callback (lambda (ok x) (declare (ignore ok x)) t))))

(test cl+ssl-refuses-pem-identity
  "PEM certificate/key files are refused in favour of a key store."
  (signals cl+ssl:ssl-error
    (cl+ssl:make-context :certificate-chain-file "/tmp/does-not-matter.pem")))

(test pure-tls-refuses-pem-ca
  "pure-tls over JSSE refuses PEM CA files rather than silently ignoring them."
  (signals pure-tls:tls-certificate-error
    (pure-tls:make-tls-context :ca-file "/tmp/does-not-matter.pem")))
