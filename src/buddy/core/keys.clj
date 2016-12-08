;; Copyright 2013-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.keys
  (:require [buddy.core.codecs :refer [str->bytes bytes->hex]]
            [clojure.java.io :as io])
  (:import org.bouncycastle.openssl.PEMParser
           org.bouncycastle.openssl.PEMEncryptedKeyPair
           org.bouncycastle.openssl.PEMKeyPair
           org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder
           org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
           org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder
           org.bouncycastle.crypto.engines.AESWrapEngine
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.Wrapper
           org.bouncycastle.asn1.pkcs.PrivateKeyInfo
           org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo
           org.bouncycastle.cert.X509CertificateHolder
           java.security.PublicKey
           java.security.PrivateKey
           java.security.Security
           java.security.SecureRandom
           java.security.KeyPair
           java.io.StringReader
           clojure.lang.Keyword))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(defn- decryptor
  [builder passphrase]
  (when (nil? passphrase)
    (throw (ex-info "Passphrase is mandatory with encrypted keys." {})))
  (.build builder (.toCharArray passphrase)))

(defn- read-pem->privkey
  [^String path ^String passphrase]
  (with-open [reader (io/reader path)]
    (let [parser    (PEMParser. reader)
          obj       (.readObject parser)
          converter (doto (JcaPEMKeyConverter.)
                      (.setProvider "BC"))]
      (cond
        (instance? PEMEncryptedKeyPair obj)
        (->> (.decryptKeyPair obj (decryptor (JcePEMDecryptorProviderBuilder.) passphrase))
             (.getKeyPair converter)
             (.getPrivate))
        (instance? PEMKeyPair obj)
        (->> (.getKeyPair converter obj)
             (.getPrivate))
        (instance? PKCS8EncryptedPrivateKeyInfo obj)
        (->> (.decryptPrivateKeyInfo obj (decryptor (JceOpenSSLPKCS8DecryptorProviderBuilder.) passphrase))
             (.getPrivateKey converter))
        (instance? PrivateKeyInfo obj)
        (.getPrivateKey converter obj)
        :else
        (throw (ex-info "Unknown PEM object type" {:kind (class obj)}))))))

(defn- read-pem->pubkey
  [path-or-reader]
  (with-open [reader (io/reader path-or-reader)]
    (let [parser    (PEMParser. reader)
          keyinfo   (.readObject parser)
          converter (doto (JcaPEMKeyConverter.)
                      (.setProvider "BC"))]
      (if (instance? X509CertificateHolder keyinfo)
        (.getPublicKey converter (.getSubjectPublicKeyInfo keyinfo))
        (.getPublicKey converter keyinfo)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Key reading functions

(defn private-key
  "Private key constructor from file path."
  ([path]
   (private-key path nil))
  ([path passphrase]
   (read-pem->privkey path passphrase)))

(defn public-key
  "Public key constructor from file path."
  [path]
  (read-pem->pubkey path))

(defn str->public-key
  "Public key constructor from string."
  [keydata]
  (with-open [reader (StringReader. ^String keydata)]
    (read-pem->pubkey reader)))

(defn str->private-key
  "Private key constructor from string."
  ([keydata]
   (str->private-key keydata nil))
  ([keydata passphrase]
   (with-open [reader (StringReader. ^String keydata)]
     (read-pem->privkey reader passphrase))))

(defn public-key?
  "Return true if key `k` is a public key."
  [k]
  (instance? PublicKey k))

(defn private-key?
  "Return true if key `k` is a private key."
  [k]
  (instance? PrivateKey k))

;; Key encryption functions

(defmulti wrap
  "Wrap a key using some of key wrapping algorithms."
  (fn [& [input secret algorithm]] algorithm) :default :aes)

(defmulti unwrap
  "Wrap a key using some of key wrapping algorithms."
  (fn [& [input secret algorithm]] algorithm) :default :aes)

(defmethod wrap :aes
  [^bytes input ^bytes secret & args]
  {:pre [(#{16 24 32} (count secret))]}
  (let [^Wrapper cipher (AESWrapEngine.)]
    (.init cipher true (KeyParameter. secret))
    (.wrap cipher input 0 (count input))))

(defmethod unwrap :aes
  [^bytes input ^bytes secret & args]
  {:pre [(#{16 24 32} (count secret))]}
  (let [^Wrapper cipher (AESWrapEngine.)]
    (.init cipher false (KeyParameter. secret))
    (.unwrap cipher input 0 (count input))))
