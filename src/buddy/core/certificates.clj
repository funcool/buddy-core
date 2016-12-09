(ns buddy.core.certificates
  (:require [clojure.java.io :as io])
  (:import java.io.StringReader
           java.security.Security
           org.bouncycastle.openssl.PEMParser
           org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
           org.bouncycastle.cert.X509CertificateHolder))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(defn- verifier [pub-key]
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

(defn str->public-key
  "Certificate constructor from string"
  [certdata]
  (with-open [reader (StringReader. ^String certdata)]
    (certificate reader)))

(defn verify
  "Verifies that the certificate is signed by the private key associated
   with the signer-public-key."
  [cert signer-public-key]
  (.isSignatureValid cert (verifier signer-public-key)))

(defn certificate?
  "Returns true if object is a certificate"
  [x]
  (instance? X509CertificateHolder x))
