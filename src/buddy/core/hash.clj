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

(ns buddy.core.hash
  "Basic crypto primitives that used for more high
  level abstractions."
  (:refer-clojure :exclude [update])
  (:require [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import org.bouncycastle.crypto.Digest
           org.bouncycastle.crypto.digests.SHA1Digest
           org.bouncycastle.crypto.digests.TigerDigest
           org.bouncycastle.crypto.digests.MD5Digest
           org.bouncycastle.crypto.digests.SHA3Digest
           org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.digests.SHA384Digest
           org.bouncycastle.crypto.digests.SHA512Digest
           org.bouncycastle.crypto.digests.Blake2bDigest
           clojure.lang.IFn
           clojure.lang.Keyword))

(def ^{:doc "Available digests."
       :dynamic true}
  *available-digests*
  {:sha256   #(SHA256Digest.)
   :sha384   #(SHA384Digest.)
   :sha512   #(SHA512Digest.)
   :sha1     #(SHA1Digest.)
   :tiger    #(TigerDigest.)
   :md5      #(MD5Digest.)
   :sha3-256 #(SHA3Digest. 256)
   :sha3-384 #(SHA3Digest. 384)
   :sha3-512 #(SHA3Digest. 512)})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocol definitions (abstractions)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IDigest
  (-digest [input engine] "Low level interface, always returns bytes"))

(defprotocol IEngine
  "Mac engine common interface definition."
  (-reset [_] "Reset the hash engine to its initial state.")
  (-update [_ input offset length] "Update bytes in a current instance.")
  (-end [_] "Return the computed mac and reset the engine."))

(extend-protocol IEngine
  Digest
  (-reset [it]
    (.reset it))
  (-update [it input offset length]
    (.update it input offset length))
  (-end [it]
    (let [buffer (byte-array (.getDigestSize it))]
      (.doFinal it buffer 0)
      buffer)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn reset!
  [engine]
  (-reset engine))

(defn update!
  ([engine input]
   (-update engine input 0 (count input)))
  ([engine input offset]
   (-update engine input offset (count input)))
  ([engine input offset length]
   (-update engine input offset length)))

(defn end!
  [engine]
  (-end engine))

(defn resolve-digest
  "Helper function for make Digest instances
  from algorithm parameter."
  [alg]
  (cond
   (instance? Keyword alg) (let [factory (*available-digests* alg)]
                             (factory))
   (instance? Digest alg) alg
   (instance? IFn alg) (alg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details for different data types.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- hash-plain-data
  [^bytes input engine]
  (-reset engine)
  (-update engine input 0 (count input))
  (-end engine))

(defn- hash-stream-data
  [^java.io.InputStream input engine]
  (-reset engine)
  (let [buffer (byte-array 5120)]
    (loop []
      (let [readed (.read input buffer 0 5120)]
        (when-not (= readed -1)
          (-update engine buffer 0 readed)
          (recur))))
    (-end engine)))

(extend-protocol IDigest
  (Class/forName "[B")
  (-digest [^bytes input engine]
    (hash-plain-data input engine))

  String
  (-digest [^String input engine]
    (hash-plain-data (str->bytes input) engine))

  java.io.InputStream
  (-digest [^java.io.InputStream input engine]
    (hash-stream-data input engine))

  java.io.File
  (-digest [^java.io.File input engine]
    (hash-stream-data (io/input-stream input) engine))

  java.net.URL
  (-digest [^java.net.URL input engine]
    (hash-stream-data (io/input-stream input) engine))

  java.net.URI
  (-digest [^java.net.URI input engine]
    (hash-stream-data (io/input-stream input) engine)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level public api.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn digest
  "Generic function for create cryptographic hash."
  [input alg-or-engine]
  (let [engine (resolve-digest alg-or-engine)]
    (-digest input engine)))

(defn blake2b
  "BLAKE2 is a cryptographic hash function faster than MD5,
  SHA-1, SHA-2, and SHA-3, yet is at least as secure as the
  latest standard SHA-3."
  [input length]
  (let [engine (Blake2bDigest. nil length nil nil)]
    (-digest input engine)))

(defn blake2b-128
  "BLAKE2 cryptographic hash function with fixed output
  digest size to 128 bits."
  [input]
  (blake2b input 16))

(defn blake2b-256
  "BLAKE2 cryptographic hash function with fixed output
  digest size to 256 bits."
  [input]
  (blake2b input 32))

(defn blake2b-512
  "BLAKE2 cryptographic hash function with fixed output
  digest size to 512 bits."
  [input]
  (blake2b input 64))

(defn sha256
  [input]
  (digest input :sha256))

(defn sha384
  [input]
  (digest input :sha384))

(defn sha512
  [input]
  (digest input :sha512))

(defn sha3-256
  [input]
  (digest input :sha3-256))

(defn sha3-384
  [input]
  (digest input :sha3-384))

(defn sha3-512
  [input]
  (digest input :sha3-512))

(defn sha1
  {:deprecated true}
  [input]
  (digest input :sha1))

(defn md5
  {:deprecated true}
  [input]
  (digest input :md5))
