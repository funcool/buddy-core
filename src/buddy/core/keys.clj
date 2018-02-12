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

(ns buddy.core.keys
  "PEM reader, JWK file reading writing and JCA conversions

   NOTE: Supports only public/private key reading - no symmetric keys support available/

   References:

   * https://tools.ietf.org/html/rfc7515
   * https://tools.ietf.org/html/rfc7517
   * https://tools.ietf.org/html/rfc7638
   * https://tools.ietf.org/html/rfc8037
   * https://www.iana.org/assignments/jose/jose.xhtml"
  (:require [buddy.core.keys.pem :as pem]
            [buddy.core.keys.jwk.proto :as jwk]
            [buddy.core.keys.jwk.okp]
            [buddy.core.keys.jwk.ec]
            [buddy.core.keys.jwk.rsa]
            [buddy.core.keys.jwk.eddsa])
  (:import org.bouncycastle.crypto.engines.AESWrapEngine
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.Wrapper
           java.security.PublicKey
           java.security.PrivateKey
           java.io.StringReader))

;; --- Public Api

;; Key reading functions

(defn private-key
  "Private key constructor from file path."
  ([path]
   (private-key path nil))
  ([path passphrase]
   (pem/read-privkey path passphrase)))

(defn public-key
  "Public key constructor from file path."
  [path]
  (pem/read-pubkey path))

(defn str->public-key
  "Public key constructor from string."
  [keydata]
  (with-open [reader (StringReader. ^String keydata)]
    (pem/read-pubkey reader)))

(defn str->private-key
  "Private key constructor from string."
  ([keydata]
   (str->private-key keydata nil))
  ([keydata passphrase]
   (with-open [reader (StringReader. ^String keydata)]
     (pem/read-privkey reader passphrase))))

(defn jwk->private-key
  "Converts clojure map representing JWK object to java.security.PrivateKey"
  [jwk]
  (jwk/jwk->private-key jwk))

(defn jwk->public-key
  "Converts clojure map representing JWK object to java.security.PublicKey"
  [jwk]
  (jwk/jwk->public-key jwk))

(defn jwk
  "Converts JCA private and public key to clojure map representing JWK object"
  [private public]
  (jwk/jwk private public))

(defn public-key->jwk
  "Converts JCA public key to clojure map representing JWK object"
  [public]
  (jwk/public-key->jwk public))

(defn jwk-thumbprint
  "Calculate the thumbprint of the jwk key according to the RFC7638."
  [jwk]
  (jwk/thumbprint jwk))

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
