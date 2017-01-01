(ns buddy.core.certificates
  (:require [clojure.java.io :as io])
  (:import java.io.StringReader
           java.security.Security
           org.bouncycastle.openssl.PEMParser
           org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
           org.bouncycastle.cert.X509CertificateHolder))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(defn- public-key-verifier
  [pub-key]
  (.build
   (doto (JcaContentVerifierProviderBuilder.)
     (.setProvider "BC"))
   pub-key))

(defn certificate
  "Reads a certificate from a PEM encoded file or stream"
  [x]
  (with-open [reader (io/reader x)]
    (let [parser (PEMParser. reader)
          keyinfo (.readObject parser)]
      keyinfo)))

(defn not-after
  "Returns the last date this signature is valid."
  [cert]
  (.getNotAfter cert))

(defn not-before
  "Returns the first date this certificate is valid."
  [cert]
  (.getNotAfter cert))

(defn valid-on-date
  "Returns true if certificate is valid date. Defaults to today"
  ([certificate date]
   (.isValidOn certificate date))
  ([certificate]
   (valid-on-date certificate (java.util.Date.))))

(defn subject
  "Returns the subject of the certificate"
  [cert]
  (.toString (.getSubject cert)))

(defn str->certificate
  "Certificate constructor from string"
  [certdata]
  (with-open [reader (StringReader. ^String certdata)]
    (certificate reader)))

(defn verify-signature
  "Verifies that the certificate is signed with the provided public key."
  [cert public-key]
  (.isSignatureValid cert (public-key-verifier public-key)))

(defn certificate?
  "Returns true if object is a certificate"
  [x]
  (instance? X509CertificateHolder x))
