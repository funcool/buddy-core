;; Copyright (c) 2013-2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.core.mac.hmac
  "Hash-based Message Authentication Codes (HMACs)"
  (:refer-clojure :exclude [hash])
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.mac.proto :as proto]
            [buddy.core.hash :as hash]
            [clojure.java.io :as io])
  (:import org.bouncycastle.crypto.macs.HMac
           org.bouncycastle.crypto.Mac
           org.bouncycastle.crypto.params.KeyParameter
           clojure.lang.Keyword
           buddy.Arrays))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level hmac engine.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hmac-engine
  "Create a hmac engine."
  [key alg]
  (let [digest (hash/resolve-digest alg)
        mac    (HMac. digest)]
    (.init mac (KeyParameter. (->byte-array key)))
    (reify
      proto/IMac
      (update [_ input offset length]
        (.update mac input offset length))
      (end [_]
        (let [buffer (byte-array (.getMacSize mac))]
          (.doFinal mac buffer 0)
          buffer)))))

(defprotocol IHMac
  (hash* [data key alg] "Generate the hmac digest for provided data.")
  (verify* [data signature key alg] "Virify the hmac digest for provided data."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details for different data types.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- hash-plain-data
  [^bytes input key ^Keyword alg]
  (let [engine (hmac-engine key alg)]
    (proto/update! engine input)
    (proto/end! engine)))

(defn- verify-plain-data
  [^bytes input, ^bytes signature, pkey, ^Keyword alg]
  (let [sig (hash-plain-data input pkey alg)]
    (Arrays/equals sig signature)))

(defn- hash-stream-data
  [^java.io.InputStream input key ^Keyword alg]
  (let [engine (hmac-engine key alg)
        buffer (byte-array 5120)]
    (loop []
      (let [readed (.read input buffer 0 5120)]
        (when-not (= readed -1)
          (proto/update! engine buffer 0 readed)
          (recur))))
    (proto/end! engine)))

(defn- verify-stream
  [^java.io.InputStream input, ^bytes signature, pkey, ^Keyword alg]
  (let [sig (hash-stream-data input pkey alg)]
    (Arrays/equals sig signature)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation of IMac protocol
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-protocol IHMac
  (Class/forName "[B")
  (hash* [^bytes input key ^Keyword alg]
    (hash-plain-data input key alg))
  (verify* [^bytes input ^bytes signature ^String key ^Keyword alg]
    (verify-plain-data input signature key alg))

  java.lang.String
  (hash* [^String input key ^Keyword alg]
    (hash-plain-data (->byte-array input) key alg))
  (verify* [^String input ^bytes signature ^String key ^Keyword alg]
    (verify-plain-data (->byte-array input) signature key alg))

  java.io.InputStream
  (hash* [^java.io.InputStream input key ^Keyword alg]
    (hash-stream-data input key alg))
  (verify* [^java.io.InputStream input ^bytes signature ^String key ^Keyword alg]
    (verify-stream input signature key alg))

  java.io.File
  (hash* [^java.io.File input key ^Keyword alg]
    (hash-stream-data (io/input-stream input) key alg))
  (verify* [^java.io.File input ^bytes signature ^String key ^Keyword alg]
    (verify-stream (io/input-stream input) signature key alg))

  java.net.URL
  (hash* [^java.net.URL input key ^Keyword alg]
    (hash-stream-data (io/input-stream input) key alg))
  (verify* [^java.net.URL input ^bytes signature ^String key ^Keyword alg]
    (verify-stream (io/input-stream input) signature key alg))

  java.net.URI
  (hash* [^java.net.URI input key ^Keyword alg]
    (hash-stream-data (io/input-stream input) key alg))
  (verify* [^java.net.URI input ^bytes signature ^String key ^Keyword alg]
    (verify-stream (io/input-stream input) signature key alg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hash
  "Generate hmac digest for arbitrary
  input data, a secret key and hash algorithm.

  If algorithm is not supplied, sha256
  will be used as default value."
  ([input key] (hash input key :sha256))
  ([input key alg]
   (hash* input key alg)))

(defn verify
  "Verify hmac for artbitrary input and signature.

  Example:
    (let [signature (hex->bytes \"61849448bdbb67b39d609471eead6...\")]
      (verify \"foo bar\" signature \"secret\" :sha256))
    ;; => true
  "
  [input ^bytes signature key ^Keyword alg]
  (verify* input signature key alg))

(def ^{:doc "Deprecated alias for `hash` function.`"
       :deprecated true}
  hmac hash)
