;;;; pure-tls-package.lisp --- The PURE-TLS drop-in package, backed by cl-jsse.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Exposes pure-tls's public API, backed by JSSE, so code written against
;;;; pure-tls can swap to this backend.  It covers the subset JSSE supports;
;;;; ACME, ECH (Encrypted Client Hello), and the post-quantum pieces are out of
;;;; scope and are not provided.

(in-package #:cl-user)

(defpackage #:pure-tls
  (:use #:cl)
  (:export
   ;; Stream creation
   #:make-tls-client-stream
   #:make-tls-server-stream
   #:with-tls-client-stream
   #:with-tls-server-stream

   ;; Context management
   #:make-tls-context
   #:tls-context-free
   #:with-tls-context
   #:*default-tls-context*

   ;; Stream classes / types
   #:tls-stream
   #:tls-client-stream
   #:tls-server-stream

   ;; Stream accessors
   #:tls-peer-certificate
   #:tls-peer-certificate-chain
   #:tls-selected-alpn
   #:tls-cipher-suite
   #:tls-version
   #:tls-client-hostname

   ;; Certificate handling
   #:certificate-subject-common-names
   #:certificate-fingerprint
   #:certificate-not-before
   #:certificate-not-after
   #:certificate-free
   #:verify-hostname

   ;; Crypto utilities
   #:random-bytes

   ;; Conditions
   #:tls-error
   #:tls-handshake-error
   #:tls-certificate-error
   #:tls-verification-error
   #:tls-alert-error

   ;; Verification modes
   #:+verify-none+
   #:+verify-peer+
   #:+verify-required+

   ;; Cipher suites
   #:+tls-aes-128-gcm-sha256+
   #:+tls-aes-256-gcm-sha384+
   #:+tls-chacha20-poly1305-sha256+

   ;; Configuration
   #:*default-buffer-size*
   #:*default-verify-mode*))
