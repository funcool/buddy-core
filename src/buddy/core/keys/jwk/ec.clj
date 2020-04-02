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

(ns buddy.core.keys.jwk.ec
  (:require [buddy.core.keys.jwk.proto :as proto]
            [buddy.core.hash :as hash]
            [cheshire.core :as json])
  (:import (java.security.interfaces ECPublicKey ECPrivateKey ECKey)
           (java.security AlgorithmParameters KeyFactory)
           (java.security.spec ECGenParameterSpec ECPoint ECParameterSpec ECPrivateKeySpec ECPublicKeySpec)
           (java.io StringWriter)
           (com.fasterxml.jackson.core JsonGenerator)))

;; EC type - curve specific
(defmulti jwkec->public-key :crv)
(defmulti jwkec->private-key :crv)

(defmethod proto/jwk->public-key "EC"
  [jwk]
  (jwkec->public-key jwk))

(defmethod proto/jwk->private-key "EC"
  [jwk]
  (jwkec->private-key jwk))

(defn- load-private [jwk curvename]
  (let [d (proto/b64str->bigint (:d jwk))
        ap (AlgorithmParameters/getInstance "EC" "BC")
        _ (.init ap (ECGenParameterSpec. curvename))
        spec (.getParameterSpec ap ECParameterSpec)
        kf (KeyFactory/getInstance "EC" "BC")]
    ;; TODO: check private and public key match
    (.generatePrivate kf (ECPrivateKeySpec. d spec))))

(defn- load-public [jwk curvename]
  (let [x (proto/b64str->bigint (:x jwk))
        y (proto/b64str->bigint (:y jwk))
        ep (ECPoint. x y)
        ap (AlgorithmParameters/getInstance "EC" "BC")
        _ (.init ap (ECGenParameterSpec. curvename))
        spec (.getParameterSpec ap ECParameterSpec)
        kf (KeyFactory/getInstance "EC" "BC")]
    (.generatePublic kf (ECPublicKeySpec. ep spec))))

(defmethod jwkec->private-key "P-256"
  [jwk]
  (load-private jwk "P-256"))

(defmethod jwkec->public-key "P-256"
  [jwk]
  (load-public jwk "P-256"))

(defmethod jwkec->private-key "P-384"
  [jwk]
  (load-private jwk "P-384"))

(defmethod jwkec->public-key "P-384"
  [jwk]
  (load-public jwk "P-384"))

(defmethod jwkec->private-key "P-521"
  [jwk]
  (load-private jwk "P-521"))

(defmethod jwkec->public-key "P-521"
  [jwk]
  (load-public jwk "P-521"))

(defn- get-curve [curvename]
  (let [paramspec (-> (doto (AlgorithmParameters/getInstance "EC" "BC")
                        (.init (ECGenParameterSpec. curvename)))
                      (.getParameterSpec ECParameterSpec))]
    (.getCurve ^ECParameterSpec paramspec)))

;; the best way i've found to convert PublicKey params to EC Name
;; is by using equals on Curve field (it checks curve params for equality)
(defn- get-curve-name [^ECKey key]
  (let [curve (.getCurve (.getParams key))]
    (condp = curve
      (get-curve "P-256")
      "P-256"
      (get-curve "P-384")
      "P-384"
      (get-curve "P-521")
      "P-521"
      ;; default
      (throw (ex-info "Unsupported EC curve (only P-256, P-384 and P-521 supported)"
                      {:key key})))))

(defn- convert-public [^ECPublicKey public]
  (let [w (.getW public)
        x (.getAffineX w)
        y (.getAffineY w)
        ;; Use public X to calculate byte length
        l (proto/calc-byte-length x)]
    {:kty "EC"
     :crv (get-curve-name public)
     :x   (proto/bigint->b64str l x)
     :y   (proto/bigint->b64str l y)}))

(defmethod proto/public-key->jwk ECPublicKey
  [^ECPublicKey public]
  (convert-public public))

(defmethod proto/jwk ECPrivateKey
  [^ECPrivateKey private ^ECPublicKey public]
  (let [public (convert-public public)
        d (.getS private)
        l (proto/calc-byte-length d)]
    (assoc public :d (proto/bigint->b64str l d))))

;; https://tools.ietf.org/html/rfc7638#section-3.2
(defmethod proto/thumbprint "EC"
  [jwk]
  (let [w (StringWriter.)
        jg ^JsonGenerator (json/create-generator w)]
    (doto jg
      (.writeStartObject)
      (.writeStringField "crv" (:crv jwk))
      (.writeStringField "kty" (:kty jwk))
      (.writeStringField "x" (:x jwk))
      (.writeStringField "y" (:y jwk))
      (.writeEndObject)
      (.flush))
    (hash/sha256 (str w))))
