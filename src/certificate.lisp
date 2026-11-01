;;;; certificate.lisp --- Accessors over peer X.509 certificates.
;;;;
;;;; Copyright (C) 2026  Anthony Green <green@moxielogic.com>
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; These read a java.security.cert.X509Certificate -- the objects
;;;; PEER-CERTIFICATE / PEER-CERTIFICATE-CHAIN return.  JSSE already verifies
;;;; the chain and hostname during the handshake; these are for callers that
;;;; want to inspect what the peer presented.

(in-package #:cl-jsse)

(defconstant +epoch-universal-offset+ 2208988800
  "Seconds between the Lisp universal-time epoch (1900) and the Unix epoch (1970).")

(defun %date->universal-time (date)
  "A java.util.Date as a Lisp universal time, or NIL for a null DATE."
  (when date
    (+ (floor (java-call "getTime()J" date) 1000) +epoch-universal-offset+)))

(defun certificate-not-before (cert)
  "The start of CERT's validity period, as a Lisp universal time."
  (%date->universal-time (java-call "getNotBefore()Ljava/util/Date;" cert)))

(defun certificate-not-after (cert)
  "The end of CERT's validity period, as a Lisp universal time."
  (%date->universal-time (java-call "getNotAfter()Ljava/util/Date;" cert)))

(defun %rdn-values (dn attribute)
  "The values of ATTRIBUTE (e.g. \"CN\") in the RFC 2253 distinguished name DN."
  (loop for part in (uiop:split-string dn :separator ",")
        for trimmed = (string-left-trim " " part)
        for eq = (position #\= trimmed)
        when (and eq (string-equal attribute (subseq trimmed 0 eq)))
          collect (subseq trimmed (1+ eq))))

(defun certificate-subject-common-names (cert)
  "CERT's subject common names (CN) as a list of strings."
  (let* ((principal (java-call "getSubjectX500Principal()Ljavax/security/auth/x500/X500Principal;" cert))
         (dn (lstring (java-call "getName()Ljava/lang/String;" principal))))
    (%rdn-values dn "CN")))

(defun certificate-subject-dn (cert)
  "CERT's subject distinguished name as an RFC 2253 string."
  (lstring (java-call "getName()Ljava/lang/String;"
                      (java-call "getSubjectX500Principal()Ljavax/security/auth/x500/X500Principal;" cert))))

(defparameter *fingerprint-algorithms*
  '((:sha1 . "SHA-1") (:sha256 . "SHA-256") (:md5 . "MD5"))
  "Keyword to java.security.MessageDigest algorithm name.")

(defun certificate-fingerprint (cert &optional (algorithm :sha1))
  "CERT's fingerprint under ALGORITHM (:sha1, :sha256, :md5), as a lowercase hex
string with no separators."
  (let* ((name (or (cdr (assoc algorithm *fingerprint-algorithms*))
                   (error 'jsse-certificate-error
                          :message (format nil "unknown fingerprint algorithm ~S" algorithm))))
         (md (java-static "java.security.MessageDigest"
                          "getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
                          (jstring name)))
         (digest (java-call "digest([B)[B" md (java-call "getEncoded()[B" cert))))
    (with-output-to-string (s)
      (loop for b in (java-array-list digest)
            do (format s "~(~2,'0x~)" (%s8->u8 b))))))

(defun %san-dns-names (cert)
  "CERT's subjectAltName dNSName entries, as a list of strings."
  (let ((collection (ignore-errors
                     (java-call "getSubjectAlternativeNames()Ljava/util/Collection;" cert))))
    (when collection
      (let ((names '()))
        (do-java-iterator (entry (java-call "iterator()Ljava/util/Iterator;" collection))
          ;; each entry is a List: (Integer type, String value); type 2 == dNSName
          (let ((type (java-call "get(I)Ljava/lang/Object;" entry 0))
                (value (java-call "get(I)Ljava/lang/Object;" entry 1)))
            (when (eql 2 (java-call "intValue()I" type))
              (push (lstring value) names))))
        (nreverse names)))))

(defun %hostname-matches-p (pattern hostname)
  "Whether HOSTNAME matches a certificate name PATTERN, honouring a single
left-most \"*\" wildcard label."
  (let ((pattern (string-downcase pattern))
        (hostname (string-downcase hostname)))
    (if (and (> (length pattern) 1) (char= (char pattern 0) #\*) (char= (char pattern 1) #\.))
        (let ((suffix (subseq pattern 1))         ; ".example.com"
              (dot (position #\. hostname)))
          (and dot (string= suffix (subseq hostname dot))))
        (string= pattern hostname))))

(defun verify-hostname (cert hostname)
  "True if CERT is valid for HOSTNAME: a matching subjectAltName dNSName, or --
only when there are no dNSName SANs -- a matching subject CN."
  (let ((dns (%san-dns-names cert)))
    (if dns
        (some (lambda (p) (%hostname-matches-p p hostname)) dns)
        (some (lambda (p) (%hostname-matches-p p hostname))
              (certificate-subject-common-names cert)))))
