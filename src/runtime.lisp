;;;; runtime.lisp --- Bringing up the OpenLDK Java runtime for JSSE.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; JSSE (javax.net.ssl.*) and the crypto providers it uses are part of the
;;;; JDK OpenLDK reads, so no external jar is needed -- unlike cl-jdbc, which
;;;; must classpath a driver jar.  START just brings the runtime up once.

(in-package #:cl-jsse)

(defvar *start-lock* (bordeaux-threads:make-lock "cl-jsse-start")
  "Serializes OpenLDK runtime startup.  Two threads entering System.initPhase1
at once corrupts the JDK's init-level sequence (\"Bad level\"), so only one
thread may bring the runtime up.")

(defun start ()
  "Start the OpenLDK Java runtime if it is not already up.  Idempotent and safe
to call from several threads at once -- the first caller brings the runtime up
while the rest wait.  MAKE-CONTEXT and the stream constructors call it for you."
  (unless (runtime-started-p)
    (bordeaux-threads:with-lock-held (*start-lock*)
      (unless (runtime-started-p)
        (start-runtime))))
  t)
