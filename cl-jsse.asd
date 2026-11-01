;;;; cl-jsse.asd --- A Common Lisp TLS interface over JSSE, running on OpenLDK.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT

(asdf:defsystem "cl-jsse"
  :description "TLS for Common Lisp over javax.net.ssl (JSSE), running on OpenLDK:
a gray-stream TLS layer driven by SSLEngine, with cl+ssl and pure-tls compat layers."
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("openldk/interop" "trivial-gray-streams" "bordeaux-threads")
  :serial t
  :components ((:file "src/package")
               (:file "src/conditions")
               (:file "src/runtime")
               (:file "src/context")
               (:file "src/engine")
               (:file "src/certificate")
               (:file "src/streams"))
  :in-order-to ((test-op (test-op "cl-jsse/tests"))))

;;; cl+ssl drop-in: defines package CL+SSL over the cl-jsse core.  Load this
;;; system to shadow the real cl+ssl with a JSSE-backed one.
(asdf:defsystem "cl-jsse/cl+ssl"
  :description "A cl+ssl-compatible API (package CL+SSL) backed by cl-jsse."
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ("cl-jsse")
  :serial t
  :components ((:module "compat"
                :serial t
                :components ((:file "cl+ssl-package")
                             (:file "cl+ssl")))))

;;; pure-tls drop-in: defines package PURE-TLS over the cl-jsse core.
(asdf:defsystem "cl-jsse/pure-tls"
  :description "A pure-tls-compatible API (package PURE-TLS) backed by cl-jsse."
  :author "Anthony Green <green@moxielogic.com>"
  :license "MIT"
  :depends-on ("cl-jsse")
  :serial t
  :components ((:module "compat"
                :serial t
                :components ((:file "pure-tls-package")
                             (:file "pure-tls")))))

(asdf:defsystem "cl-jsse/tests"
  :description "Tests for cl-jsse."
  :depends-on ("cl-jsse" "cl-jsse/cl+ssl" "cl-jsse/pure-tls" "fiveam" "usocket" "bordeaux-threads")
  :serial t
  :components ((:module "tests"
                :components ((:file "tests"))))
  :perform (test-op (op c)
             (unless (uiop:symbol-call :fiveam :run! (uiop:find-symbol* :cl-jsse :cl-jsse/tests))
               (error "cl-jsse tests failed"))))
