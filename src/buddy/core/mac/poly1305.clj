;; Copyright 2013-2015 Andrey Antukh <niwi@niwi.be>
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


(ns buddy.core.mac.poly1305
  "Poly1305-AES is a cryptographic message authentication code
  (MAC) written by Daniel J. Bernstein. It can be used to verify the
  data integrity and the authenticity of a message.

  The security of Poly1305-AES is very close to the underlying AES
  block cipher algorithm. As a result, the only way for an attacker
  to break Poly1305-AES is to break AES.

  Poly1305-AES offers also cipher replaceability. If anything does
  go wrong with AES, it can be substituted with identical security
  guarantee."
  (:refer-clojure :exclude [hash])
  (:require [buddy.core.hash :as hash]
            [buddy.core.nonce :as nonce]
            [buddy.core.mac.proto :as proto]
            [buddy.core.codecs :as codecs :refer :all]
            [clojure.java.io :as io])
  (:import org.bouncycastle.crypto.generators.Poly1305KeyGenerator
           org.bouncycastle.crypto.macs.Poly1305
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.params.ParametersWithIV
           org.bouncycastle.crypto.engines.AESFastEngine
           org.bouncycastle.crypto.engines.SerpentEngine
           org.bouncycastle.crypto.engines.TwofishEngine
           org.bouncycastle.crypto.BlockCipher
           clojure.lang.IFn
           clojure.lang.Keyword))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level hmac engine.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^{:doc "Default engine factories."
       :dynamic true}
  *available-engines* {:aes     #(AESFastEngine.)
                       :serpent #(SerpentEngine.)
                       :twofish #(TwofishEngine.)})

(def ^{:private true
       :static true
       :doc "Length in bytes of poly1305 output."}
  poly1305-output-size 16)

(defn- resolve-engine
  "Given dynamic type engine, try resolve it to
  valid engine instance. By default accepts keywords
  and functions."
  [engine]
  (cond
   (instance? Keyword engine) (let [factory (engine *available-engines*)]
                                (factory))
   (instance? IFn engine) (engine)
   (instance? BlockCipher engine) engine))

(defn- key->polykey
  "Noramalizes 32 bytes array key to poly1305
  formatted byte array key."
  [^bytes key]
  {:pre [(= (count key) 32)]}
  (let [key (clone-byte-array key)]
    (Poly1305KeyGenerator/clamp key)
    key))

(defn poly1305-engine
  "Create a poly1305 mac engine."
  [^bytes key ^bytes iv ^Keyword alg]
  {:pre [(= (count iv) 16)
         (= (count key) 32)]}
  (let [engine (resolve-engine alg)
        mac    (Poly1305. engine)
        kp     (KeyParameter. (key->polykey key))]
    (.init mac (ParametersWithIV. kp iv))
    (reify
      proto/IMac
      (update [_ input offset length]
        (.update mac input offset length))
      (end [_]
        (let [buffer (byte-array (.getMacSize mac))]
          (.doFinal mac buffer 0)
          buffer)))))

(defprotocol IPoly1305Mac
  (^:private hash* [data key alg] "Generate the poly1305 digest for provided data.")
  (^:private verify* [data signature key alg] "Virify the poly1305 digest for provided data."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Internal implementations
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- hash-plain-data
  "Calculate the message authentication code
  for byte array objects using poly1305 algorithm."
  ([^bytes input ^bytes key ^Keyword alg]
   (let [iv (nonce/random-nonce 16)]
     (hash-plain-data input key iv alg)))
  ([^bytes input ^bytes key ^bytes iv ^Keyword alg]
   (let [key (hash/sha256 key) ;; Normalizes an arbitrary length key to 32 bytes.
         engine (poly1305-engine key iv alg)]
     (proto/update! engine input)
     (let [result (proto/end! engine)]
       (concat-byte-arrays result iv)))))

(defn- hash-stream-data
  "Calculate the poly1305 message authentication code
  for file like objects in most memory efficient way."
  ([^java.io.InputStream input ^bytes key ^Keyword alg]
   (let [iv (nonce/random-nonce 16)]
     (hash-stream-data input key iv alg)))
  ([^java.io.InputStream input ^bytes key ^bytes iv ^Keyword alg]
   (let [key (hash/sha256 key) ;; Normalizes an arbitrary length key to 32 bytes.
         engine (poly1305-engine key iv alg)
         buffer (byte-array 5120)]
     (loop []
       (let [readed (.read input buffer 0 5120)]
         (when-not (= readed -1)
           (proto/update! engine buffer 0 readed)
           (recur))))
     (let [result (proto/end! engine)]
       (concat-byte-arrays result iv)))))

(defn- verify-plain-data
  "Generic implementation of verify proces of
  poly1305 mac digest."
  [^bytes input ^bytes signature ^bytes key ^Keyword alg]
  (let [outputsize poly1305-output-size
        iv (codecs/clone-byte-array signature outputsize (count signature))
        sig (hash-plain-data input key iv alg)]
    (codecs/equals? sig signature)))

(defn- verify-stream-data
  "Generic implementation of verify proces of
  poly1305 mac digest."
  [^bytes input ^bytes signature ^bytes key ^Keyword alg]
  (let [outputsize poly1305-output-size
        iv (clone-byte-array signature outputsize (count signature))
        sig (hash-stream-data input key iv alg)]
    (codecs/equals? sig signature)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-protocol IPoly1305Mac
  (Class/forName "[B")
  (hash* [^bytes input ^bytes key ^Keyword alg]
    (hash-plain-data input key alg))
  (verify* [^bytes input ^bytes signature ^String key ^Keyword alg]
    (verify-plain-data input signature key alg))

  java.lang.String
  (hash* [^String input ^bytes key ^Keyword alg]
    (hash-plain-data (->byte-array input) key alg))
  (verify* [^String input ^bytes signature ^String key ^Keyword alg]
    (verify-plain-data (->byte-array input) signature key alg))

  java.io.InputStream
  (hash* [^java.io.InputStream input ^bytes key ^Keyword alg]
    (hash-stream-data input key alg))
  (verify* [^java.io.File input ^bytes signature ^String key ^Keyword alg]
    (verify-stream-data (io/input-stream input) signature key alg))

  java.io.File
  (hash* [^java.io.File input ^bytes key ^Keyword alg]
    (hash-stream-data (io/input-stream input) key alg))
  (verify* [^java.io.File input ^bytes signature ^String key ^Keyword alg]
    (verify-stream-data (io/input-stream input) signature key alg))

  java.net.URL
  (hash* [^java.net.URL input ^bytes key ^Keyword alg]
    (hash-stream-data (io/input-stream input) key alg))
  (verify* [^java.net.URL input ^bytes signature ^String key ^Keyword alg]
    (verify-stream-data (io/input-stream input) signature key alg))

  java.net.URI
  (hash* [^java.net.URI input ^bytes key ^Keyword alg]
    (hash-stream-data (io/input-stream input) key alg))
  (verify* [^java.net.URI input ^bytes signature ^String key ^Keyword alg]
    (verify-stream-data (io/input-stream input) signature key alg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level interface
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn hash
  "Generate poly1305 digest for arbitrary
  input data, a secret key and crypto algorithm.

  If algorithm is not supplied, aes will be used
  as default value."
  ([input key] (hash input key :aes))
  ([input key alg]
   (hash* input key alg)))

(defn verify
  "Verify poly1305 mac for specified data and signature."
  [input ^bytes signature key ^Keyword alg]
  (verify* input signature key alg))

(def ^{:doc "Deprecated alias for `hash` function.`"
       :deprecated true}
  poly1305 hash)
