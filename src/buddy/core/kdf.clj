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

(ns buddy.core.kdf
  "Key derivation function interface."
  (:require [buddy.core.hash :as hash]
            [buddy.core.codecs :as codecs])
  (:import org.bouncycastle.crypto.generators.KDF1BytesGenerator
           org.bouncycastle.crypto.generators.KDF2BytesGenerator
           org.bouncycastle.crypto.generators.HKDFBytesGenerator
           org.bouncycastle.crypto.generators.KDFCounterBytesGenerator
           org.bouncycastle.crypto.generators.KDFFeedbackBytesGenerator
           org.bouncycastle.crypto.generators.KDFDoublePipelineIterationBytesGenerator
           org.bouncycastle.crypto.params.HKDFParameters
           org.bouncycastle.crypto.params.KDFParameters
           org.bouncycastle.crypto.params.KDFCounterParameters
           org.bouncycastle.crypto.params.KDFFeedbackParameters
           org.bouncycastle.crypto.params.KDFDoublePipelineIterationParameters
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
           org.bouncycastle.crypto.macs.HMac
           org.bouncycastle.crypto.DerivationFunction
           org.bouncycastle.crypto.Mac
           java.nio.ByteBuffer
           clojure.lang.Keyword))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Constants
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:const +pbkdf2-iterations+ 1000)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocol
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IKDF
  (-get-bytes [_ length] "Get the next N bytes from kdf."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Public Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti engine
  "Key derivation function engine constructor."
  :alg)

(defn get-bytes
  [engine length]
  (-get-bytes engine length))

(defn get-buffer
  [engine length]
  (ByteBuffer/wrap (-get-bytes engine length)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-protocol IKDF
  DerivationFunction
  (-get-bytes [it length]
    (let [buffer (byte-array length)]
      (.generateBytes it buffer 0 length)
      buffer)))

(extend-protocol IKDF
  PKCS5S2ParametersGenerator
  (-get-bytes [it length]
    (.getKey ^KeyParameter (.generateDerivedParameters it (* 8 length)))))

(defmethod engine :hkdf
  [{:keys [key salt info digest]}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        info (when info (codecs/to-bytes info))
        params (HKDFParameters. key salt info)
        digest (hash/resolve-digest-engine digest)
        engine (HKDFBytesGenerator. digest)]
    (.init engine params)
    engine))

(defmethod engine :hkdf+sha256
  [options]
  (engine (assoc options :alg :hkdf :digest :sha256)))

(defmethod engine :hkdf+sha386
  [options]
  (engine (assoc options :alg :hkdf :digest :sha386)))

(defmethod engine :hkdf+sha512
  [options]
  (engine (assoc options :alg :hkdf :digest :sha512)))

(defmethod engine :hkdf+blake2b-512
  [options]
  (engine (assoc options :alg :hkdf :digest :blake2b-512)))

(defmethod engine :kdf1
  [{:keys [key salt digest]}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        params (KDFParameters. key salt)
        digest (hash/resolve-digest-engine digest)
        engine (KDF1BytesGenerator. digest)]
    (.init engine params)
    engine))

(defmethod engine :kdf1+sha256
  [options]
  (engine (assoc options :alg :kdf1 :digest :sha256)))

(defmethod engine :kdf1+sha386
  [options]
  (engine (assoc options :alg :kdf1 :digest :sha386)))

(defmethod engine :kdf1+sha512
  [options]
  (engine (assoc options :alg :kdf1 :digest :sha512)))

(defmethod engine :kdf1+blake2b-512
  [options]
  (engine (assoc options :alg :kdf1 :digest :blake2b-512)))

(defmethod engine :kdf2
  [{:keys [key salt digest]}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        params (KDFParameters. key salt)
        digest (hash/resolve-digest-engine digest)
        engine (KDF2BytesGenerator. digest)]
    (.init engine params)
    engine))

(defmethod engine :kdf2+sha256
  [options]
  (engine (assoc options :alg :kdf2 :digest :sha256)))

(defmethod engine :kdf2+sha386
  [options]
  (engine (assoc options :alg :kdf2 :digest :sha386)))

(defmethod engine :kdf2+sha512
  [options]
  (engine (assoc options :alg :kdf2 :digest :sha512)))

(defmethod engine :kdf2+blake2b-512
  [options]
  (engine (assoc options :alg :kdf2 :digest :blake2b-512)))

(defmethod engine :cmkdf
  [{:keys [key salt digest r] :or {r 32}}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        params (KDFCounterParameters. key salt r)
        digest (hash/resolve-digest-engine digest)
        mac (HMac. digest)
        engine (KDFCounterBytesGenerator. mac)]
    (.init engine params)
    engine))

(defmethod engine :cmkdf+sha256
  [options]
  (engine (assoc options :alg :cmkdf :digest :sha256)))

(defmethod engine :cmkdf+sha386
  [options]
  (engine (assoc options :alg :cmkdf :digest :sha386)))

(defmethod engine :cmkdf+sha512
  [options]
  (engine (assoc options :alg :cmkdf :digest :sha512)))

(defmethod engine :cmkdf+blake2b-512
  [options]
  (engine (assoc options :alg :cmkdf :digest :blake2b-512)))

(defmethod engine :fmkdf
  [{:keys [key salt digest r counter] :or {r 32 counter true}}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        params (if counter
                 (KDFFeedbackParameters/createWithCounter key salt nil r)
                 (KDFFeedbackParameters/createWithoutCounter key salt nil))
        digest (hash/resolve-digest-engine digest)
        mac (HMac. digest)
        engine (KDFFeedbackBytesGenerator. mac)]
    (.init engine params)
    engine))

(defmethod engine :fmkdf+sha256
  [options]
  (engine (assoc options :alg :fmkdf :digest :sha256)))

(defmethod engine :fmkdf+sha386
  [options]
  (engine (assoc options :alg :fmkdf :digest :sha386)))

(defmethod engine :fmkdf+sha512
  [options]
  (engine (assoc options :alg :fmkdf :digest :sha512)))

(defmethod engine :fmkdf+blake2b-512
  [options]
  (engine (assoc options :alg :fmkdf :digest :blake2b-512)))

(defmethod engine :dpimkdf
  [{:keys [key salt digest r counter] :or {r 32 counter true}}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        params (if counter
                 (KDFDoublePipelineIterationParameters/createWithCounter key salt r)
                 (KDFDoublePipelineIterationParameters/createWithoutCounter key salt))
        digest (hash/resolve-digest-engine digest)
        mac (HMac. digest)
        engine (KDFDoublePipelineIterationBytesGenerator. mac)]
    (.init engine params)
    engine))

(defmethod engine :dpimkdf+sha256
  [options]
  (engine (assoc options :alg :dpimkdf :digest :sha256)))

(defmethod engine :dpimkdf+sha386
  [options]
  (engine (assoc options :alg :dpimkdf :digest :sha386)))

(defmethod engine :dpimkdf+sha512
  [options]
  (engine (assoc options :alg :dpimkdf :digest :sha512)))

(defmethod engine :dpimkdf+blake2b-512
  [options]
  (engine (assoc options :alg :dpimkdf :digest :blake2b-512)))

(defmethod engine :pbkdf2
  [{:keys [key salt digest iterations]}]
  (let [key (codecs/to-bytes key)
        salt (codecs/to-bytes salt)
        digest (hash/resolve-digest-engine digest)
        engine (PKCS5S2ParametersGenerator. digest)]
    (.init engine key salt (or iterations +pbkdf2-iterations+))
    engine))

(defmethod engine :pbkdf2+sha256
  [options]
  (engine (assoc options :alg :pbkdf2 :digest :sha256)))

(defmethod engine :pbkdf2+sha384
  [options]
  (engine (assoc options :alg :pbkdf2 :digest :sha384)))

(defmethod engine :pbkdf2+sha512
  [options]
  (engine (assoc options :alg :pbkdf2 :digest :sha512)))
