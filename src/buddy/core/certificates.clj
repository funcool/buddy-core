;; Copyright (c) 2015-2016 Andrey Antukh <niwi@niwi.nz>
;;
;; Licensed under the Apache License, Version 2.0 (the "License")
;; you may not use this file except in compliance with the License.
;; You may obtain a copy of the License at
;;
;;     http://www.apache.org/licenses/LICENSE-2.0
;;
;; Unless required by applicable law or agreed to in writing, software
;; distributed under the License is distributed on an "AS IS" BASIS,
;; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
;; See the License for the specific language governing permissions and
;; limitations under the License.

(ns buddy.core.certificates
  (:require [clojure.java.io :as io])
  (:import
   java.io.StringReader
   java.security.Security
   java.security.PublicKey
   org.bouncycastle.openssl.PEMParser
   org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
   org.bouncycastle.cert.X509CertificateHolder))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(defn- public-key-verifier
  [pub-key]
  (let [builder (doto (JcaContentVerifierProviderBuilder.)
                      (.setProvider "BC"))]
    (cond
      (instance? X509CertificateHolder pub-key)
        (.build builder ^X509CertificateHolder pub-key)
      (instance? PublicKey pub-key)
        (.build builder ^PublicKey pub-key)
      :else
        (throw (Exception. "Unknown public key type" {:kind (class pub-key)})))))

(defn certificate
  "Reads a certificate from a PEM encoded file or stream"
  [x]
  (with-open [reader (io/reader x)]
    (let [parser (PEMParser. reader)
          keyinfo (.readObject parser)]
      keyinfo)))

(defn not-after
  "Returns the last date this signature is valid."
  [^X509CertificateHolder cert]
  (.getNotAfter cert))

(defn not-before
  "Returns the first date this certificate is valid."
  [^X509CertificateHolder cert]
  [cert]
  (.getNotBefore cert))

(defn valid-on-date?
  "Returns true if certificate is valid date. Defaults to today"
  ([^X509CertificateHolder certificate date]
   (.isValidOn certificate date))
  ([^X509CertificateHolder certificate]
   (valid-on-date? certificate (java.util.Date.))))

(defn subject
  "Returns the subject of the certificate"
  [^X509CertificateHolder cert]
  (.toString (.getSubject cert)))

(defn str->certificate
  "Certificate constructor from string"
  [certdata]
  (with-open [reader (StringReader. ^String certdata)]
    (certificate reader)))

(defn verify-signature
  "Verifies that the certificate is signed with the provided public key."
  [^X509CertificateHolder cert public-key]
  (.isSignatureValid cert (public-key-verifier public-key)))

(defn certificate?
  "Returns true if object is a certificate"
  [x]
  (instance? X509CertificateHolder x))
