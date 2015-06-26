;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.mac.shmac
  "Salted variant of Hash-based Message Authentication Codes (HMACs)"
  (:refer-clojure :exclude [hash])
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.hash :as hash])
  (:import clojure.lang.Keyword))

(defn- make-salted-hmac
  [input key salt ^Keyword alg]
  (let [key (bytes/concat (->byte-array key)
                          (->byte-array salt))]
    (hmac/hash input (hash/sha512 key) alg)))

(defn- verify-salted-hmac
  [input ^bytes signature key salt ^Keyword alg]
  (let [key (bytes/concat (->byte-array key)
                          (->byte-array salt))]
    (hmac/verify input signature (hash/sha512 key) alg)))

(defn hash
  "Generate salted hmac digest for arbitrary
  input data, a secret key and hash algorithm.

  If algorithm is not supplied, sha256
  will be used as default value."
  [input key salt ^Keyword alg]
  (make-salted-hmac input key salt alg))

(def ^{:doc "Deprecated alias for `hash` function.`"
       :deprecated true}
  shmac hash)

(defn verify
  "Generic function that exposes a high level
  interface for salted variant of keyed-hash message
  authentication code verification algorithm."
  [input ^bytes signature key salt ^Keyword alg]
  (verify-salted-hmac input signature key salt alg))

