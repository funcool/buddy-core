;; Copyright 2013-2015 Andrey Antukh <niwi@niwi.nz>
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
           org.bouncycastle.crypto.engines.AESWrapEngine
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.Wrapper
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

(defn- read-pem->keypair
  [^String path ^String passphrase]
  (with-open [reader (io/reader path)]
    (let [parser    (PEMParser. reader)
          keypair   (.readObject parser)
          converter (doto (JcaPEMKeyConverter.)
                      (.setProvider "BC"))]
      (if (instance? PEMEncryptedKeyPair keypair)
        (do
          (when (nil? passphrase)
            (throw (ex-info "Phassphrase is mandatory with encrypted keys." {})))
          (let [builder   (JcePEMDecryptorProviderBuilder.)
                decryptor (.build builder (.toCharArray passphrase))]
            (->> (.decryptKeyPair keypair decryptor)
                 (.getKeyPair converter))))
        (.getKeyPair converter keypair)))))

(defn- read-pem->pubkey
  [path-or-reader]
  (with-open [reader (io/reader path-or-reader)]
    (let [parser    (PEMParser. reader)
          keyinfo   (.readObject parser)
          converter (doto (JcaPEMKeyConverter.)
                      (.setProvider "BC"))]
      (.getPublicKey converter keyinfo))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Key reading functions

(defn private-key
  "Private key constructor from file path."
  [^String path & [^String passphrase]]
  (let [keypair (read-pem->keypair path passphrase)]
    (.getPrivate keypair)))

(defn public-key
  "Public key constrcutor from file path."
  [^String path]
  (read-pem->pubkey path))

(defn str->public-key
  "Public key constructor from string."
  [^String keydata]
  (with-open [reader (StringReader. keydata)]
    (read-pem->pubkey reader)))

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
