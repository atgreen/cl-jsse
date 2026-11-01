;;;; package.lisp --- Package definition for the cl-jsse native core.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; cl-jsse wraps a caller-provided Lisp byte stream in TLS, driving the
;;;; handshake and record layer with javax.net.ssl.SSLEngine on OpenLDK.  The
;;;; native API here is shaped to echo pure-tls's public surface, so the cl+ssl
;;;; and pure-tls compatibility layers can stay thin translations over it.

(in-package #:cl-user)

(defpackage #:cl-jsse
  (:use #:cl #:trivial-gray-streams)
  (:import-from #:openldk.interop
                #:start-runtime #:runtime-started-p
                #:java-load #:java-new #:java-call #:java-static #:java-static-field
                #:jstring #:lstring #:make-java-array-of #:java-array-list
                #:java-instance-p #:with-foreign-errors #:define-java-class
                #:make-java-object #:foreign-error #:foreign-error-message
                #:foreign-error-object #:do-java-iterator)
  (:export
   ;; Runtime
   #:start

   ;; Context management
   #:make-context
   #:context-free
   #:with-context
   #:*default-context*

   ;; Stream creation
   #:make-client-stream
   #:make-server-stream
   #:with-client-stream
   #:with-server-stream

   ;; Stream classes
   #:jsse-stream
   #:jsse-client-stream
   #:jsse-server-stream

   ;; Stream accessors
   #:peer-certificate
   #:peer-certificate-chain
   #:selected-alpn
   #:cipher-suite
   #:protocol-version
   #:client-hostname

   ;; Certificate accessors
   #:certificate-subject-common-names
   #:certificate-not-before
   #:certificate-not-after
   #:certificate-fingerprint
   #:verify-hostname

   ;; Verification modes
   #:+verify-none+
   #:+verify-peer+
   #:+verify-required+

   ;; Conditions
   #:jsse-error
   #:jsse-handshake-error
   #:jsse-verification-error
   #:jsse-certificate-error
   #:jsse-error-message))
