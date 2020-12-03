;; Copyright (c) 2014-2018 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.keys.pem
  "PEM reading implementation."
  (:require [clojure.java.io :as io])
  (:import org.bouncycastle.openssl.PEMParser
           org.bouncycastle.openssl.PEMEncryptedKeyPair
           org.bouncycastle.openssl.PEMKeyPair
           org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
           org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
           org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
           org.bouncycastle.asn1.pkcs.PrivateKeyInfo
           org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
           org.bouncycastle.cert.X509CertificateHolder
           java.security.PublicKey
           java.security.PrivateKey
           java.security.Security
           java.security.KeyPair))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(defn- decryptor
  [^String passphrase]
  (when (nil? passphrase)
    (throw (ex-info "Passphrase is mandatory with encrypted keys." {})))
  (.toCharArray passphrase))

;; TODO: maybe make this functions work with strings instead of reader

(defn read-privkey
  [path-or-reader ^String passphrase]
  (with-open [reader (io/reader path-or-reader)]
    (let [parser    (PEMParser. reader)
          obj       (.readObject parser)
          converter (doto (JcaPEMKeyConverter.)
                      (.setProvider "BC"))]
      (cond
        (instance? PEMEncryptedKeyPair obj)
        (->> (.decryptKeyPair ^PEMEncryptedKeyPair obj (.build (JcePEMDecryptorProviderBuilder.) (decryptor passphrase)))
             (.getKeyPair converter)
             (.getPrivate))
        (instance? PEMKeyPair obj)
        (->> (.getKeyPair converter obj)
             (.getPrivate))
        (instance? PKCS8EncryptedPrivateKeyInfo obj)
        (->> (.decryptPrivateKeyInfo ^PKCS8EncryptedPrivateKeyInfo obj (.build (JceOpenSSLPKCS8DecryptorProviderBuilder.) (decryptor passphrase)))
             (.getPrivateKey converter))
        (instance? PrivateKeyInfo obj)
        (.getPrivateKey converter obj)
        :else
        (throw (ex-info "Unknown PEM object type" {:kind (class obj)}))))))

(defn read-pubkey
  [path-or-reader]
  (with-open [reader (io/reader path-or-reader)]
    (let [parser    (PEMParser. reader)
          keyinfo   (.readObject parser)
          converter (doto (JcaPEMKeyConverter.)
                      (.setProvider "BC"))]
      (if (instance? X509CertificateHolder keyinfo)
        (.getPublicKey converter (.getSubjectPublicKeyInfo ^X509CertificateHolder keyinfo))
        (.getPublicKey converter keyinfo)))))

