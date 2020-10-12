;; Copyright (c) 2014-2018 Andrey Antukh <niwi@niwi.nz>
;; Copyright (c) 2017-2018 Denis Shilov <sxp@bk.ru>
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

(ns buddy.core.keys.jwk.eddsa
  "JWK support for EdDSA keys"
  (:require [buddy.core.codecs :as codecs]
            [buddy.core.codecs.base64 :as base64]
            [buddy.core.keys.jwk.proto :as proto]
            [buddy.core.keys.jwk.okp :as okp])
  (:import (org.bouncycastle.crypto.params Ed25519PrivateKeyParameters Ed25519PublicKeyParameters AsymmetricKeyParameter)
           (org.bouncycastle.jcajce.provider.asymmetric.edec BCEdDSAPrivateKey BCEdDSAPublicKey)
           (java.util Arrays)))

(defn- construct
  [cls params]
  ; HACK: These constructors are not public
  (let [cons (vec (.getDeclaredConstructors cls))
        ctor (first (filter #(and
                               (= 1 (.getParameterCount %))
                               (= AsymmetricKeyParameter (aget (.getParameterTypes %) 0)))
                      cons))]
    (when-not (some? ctor)
      (throw (UnsupportedOperationException. "Can not get key constructor")))
    (.setAccessible ctor true)
    (.newInstance ctor (to-array [params]))))

(defn pkcs8-key
  [encoded]
  (Arrays/copyOfRange encoded 16 48))

(defn x509-key
  [encoded]
  (Arrays/copyOfRange encoded 12 44))

(defn bc-ed-private-key
  [params]
  (construct BCEdDSAPrivateKey params))

(defn bc-ed-public-key
  [params]
  (construct BCEdDSAPublicKey params))

(defn- pubkey
  [jwk]
  (-> (:x jwk)
    ;(codecs/b64->bytes)
    (base64/decode)
    (Ed25519PublicKeyParameters. 0)
    (bc-ed-public-key)))

(defn- verify-public-key!
  [priv pub]
  ;; Check for incorrect public key
  (let [pub-buf (.getEncoded pub)
        pub2-buf (-> (.getPublicKey priv) (.getEncoded))]
    (when-not (Arrays/equals pub-buf pub2-buf)
      (throw (ex-info "Public key doesn't match private key"
               {:expected (codecs/bytes->hex pub-buf)
                :actual (codecs/bytes->hex pub2-buf)})))))

(defmethod okp/jwkokp->private-key "Ed25519"
  [jwk]
  (let [priv (-> (:d jwk)
               ;(codecs/to-bytes)
               ;(codecs/b64->bytes)
               (base64/decode)
               (Ed25519PrivateKeyParameters. 0)
               (bc-ed-private-key))
        pub (pubkey jwk)]
    (verify-public-key! priv pub)
    priv))

(defmethod okp/jwkokp->public-key "Ed25519"
  [jwk]
  (pubkey jwk))

(defmethod proto/jwk BCEdDSAPrivateKey
  [^BCEdDSAPrivateKey private ^BCEdDSAPublicKey public]
  (verify-public-key! private public)
  {:kty "OKP"
   :crv "Ed25519"
   :d (proto/bytes->b64str (pkcs8-key (.getEncoded private)))
   :x (proto/bytes->b64str (x509-key (.getEncoded public)))})

(defmethod proto/public-key->jwk BCEdDSAPublicKey
  [^BCEdDSAPublicKey public]
  {:kty "OKP"
   :crv "Ed25519"
   :x (proto/bytes->b64str (x509-key (.getEncoded public)))})
