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
  (:require [buddy.core.codecs.base64 :as b64]
            [buddy.core.codecs :as codecs]
            [buddy.core.keys.jwk.proto :as proto]
            [buddy.core.keys.jwk.okp :as okp]
            [cheshire.core :as json])
  (:import (net.i2p.crypto.eddsa EdDSAPrivateKey EdDSAPublicKey)
           (net.i2p.crypto.eddsa.spec EdDSANamedCurveTable EdDSAPrivateKeySpec EdDSAPublicKeySpec EdDSAParameterSpec)
           (java.util Arrays)
           (com.fasterxml.jackson.core JsonGenerator)
           (java.io StringWriter)))

(def ^:private ^EdDSAParameterSpec ed25519 (EdDSANamedCurveTable/getByName "Ed25519"))

(defmethod okp/jwkokp->private-key "Ed25519"
  [jwk]
  (let [seedhash (:d jwk)
        priv (EdDSAPrivateKey.
               (EdDSAPrivateKeySpec.
                 ^bytes (b64/decode seedhash)
                 ed25519))
        pub (EdDSAPublicKey.
              (EdDSAPublicKeySpec.
                (.getA priv)
                ed25519))
        ;; public key calculated from private key
        expected (.getAbyte priv)
        ;; public key from file
        actual ^bytes (b64/decode (:x jwk))]
    ;; Check for incorrect public key
    (when-not (Arrays/equals expected actual)
      (throw (ex-info "Public key doesn't match private key"
                      {:expected (codecs/bytes->hex expected)
                       :actual   (codecs/bytes->hex actual)})))
    priv))

(defmethod okp/jwkokp->public-key "Ed25519"
  [jwk]
  (EdDSAPublicKey.
    (EdDSAPublicKeySpec.
      ^bytes (b64/decode (:x jwk))
      ed25519)))

(defmethod proto/jwk EdDSAPrivateKey
  [^EdDSAPrivateKey private ^EdDSAPublicKey public]
  ;; TODO: check public/private keys match
  {:kty "OKP"
   :crv "Ed25519"
   :d   (proto/bytes->b64str (.getSeed private))
   :x   (proto/bytes->b64str (.getAbyte public))})

(defmethod proto/public-key->jwk EdDSAPublicKey
  [^EdDSAPublicKey public]
  {:kty "OKP"
   :crv "Ed25519"
   :x   (proto/bytes->b64str (.getAbyte public))})
