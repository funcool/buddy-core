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
  (:refer-clojure :exclude [update reset!])
  (:require [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import
   org.bouncycastle.crypto.Digest
   org.bouncycastle.crypto.digests.SHA1Digest
   org.bouncycastle.crypto.digests.TigerDigest
   org.bouncycastle.crypto.digests.MD5Digest
   org.bouncycastle.crypto.digests.RIPEMD128Digest
   org.bouncycastle.crypto.digests.RIPEMD160Digest
   org.bouncycastle.crypto.digests.RIPEMD256Digest
   org.bouncycastle.crypto.digests.RIPEMD320Digest
   org.bouncycastle.crypto.digests.SHA3Digest
   org.bouncycastle.crypto.digests.SHA256Digest
   org.bouncycastle.crypto.digests.SHA384Digest
   org.bouncycastle.crypto.digests.SHA512Digest
   org.bouncycastle.crypto.digests.Blake2bDigest
   org.bouncycastle.crypto.digests.Blake3Digest
   org.bouncycastle.crypto.digests.SkeinDigest
   org.bouncycastle.crypto.digests.WhirlpoolDigest))

(def ^:no-doc ^:static
  +digest-engines+
  {:sha256      #(SHA256Digest.)
   :sha384      #(SHA384Digest.)
   :sha512      #(SHA512Digest.)
   :sha1        #(SHA1Digest.)
   :ripemd128   #(RIPEMD128Digest.)
   :ripemd160   #(RIPEMD160Digest.)
   :ripemd256   #(RIPEMD256Digest.)
   :ripemd320   #(RIPEMD320Digest.)
   :tiger       #(TigerDigest.)
   :md5         #(MD5Digest.)
   :sha3-256    #(SHA3Digest. 256)
   :sha3-384    #(SHA3Digest. 384)
   :sha3-512    #(SHA3Digest. 512)
   :blake2b-128 #(Blake2bDigest. nil 16 nil nil)
   :blake2b-256 #(Blake2bDigest. nil 32 nil nil)
   :blake2b-512 #(Blake2bDigest. nil 64 nil nil)
   :blake3-128  #(Blake3Digest. 128)
   :blake3-256  #(Blake3Digest. 256)
   :blake3-512  #(Blake3Digest. 512)
   :skein-256   #(SkeinDigest. 256 256)
   :skein-512   #(SkeinDigest. 512 512)
   :skein-1024  #(SkeinDigest. 1024 1024)
   :whirlpool   #(WhirlpoolDigest.)})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocol definitions (abstractions)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IDigest
  (-digest [input engine] "Low level interface, always returns bytes"))

(defprotocol IEngine
  "Hash engine common interface definition."
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

(defn resolve-digest-engine
  "Helper function for make Digest instances
  from algorithm parameter."
  [engine]
  (cond
   (keyword? engine)
   (when-let [factory (get +digest-engines+ engine)]
     (factory))
   (instance? Digest engine) engine
   (fn? engine) (engine)))

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
    (with-open [is (io/input-stream input)]
      (hash-stream-data is engine)))

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
  (let [engine (resolve-digest-engine alg-or-engine)]
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
  (digest input :blake2b-128))

(defn blake2b-256
  "BLAKE2 cryptographic hash function with fixed output
  digest size to 256 bits."
  [input]
  (digest input :blake2b-256))

(defn blake2b-512
  "BLAKE2 cryptographic hash function with fixed output
  digest size to 512 bits."
  [input]
  (digest input :blake2b-512))

(defn blake3
  "BLAKE3 is a cryptographic hash function faster than MD5,
  SHA-1, SHA-2, SHA-3, and BLAKE2. It focuses on speed."
  [input length]
  (let [length (* length 8)
        engine (Blake3Digest. ^int length)]
    (-digest input engine)))

(defn blake3-256
  "BLAKE3 cryptographic hash function with fixed output
  digest size to 256 bits."
  [input]
  (digest input :blake3-256))

(defn skein
  "Skein is a cryptographic hash function based on
  Threefish tweakable block cipher compressed using
  Unique Block Iteration and is one of five finalists
  in the NIST hash function competition for SHA3."
  ([input state]
   (skein input state state))
  ([input state length]
   (let [state (* state 8)
         length (* length 8)
         engine (SkeinDigest. state length)]
     (-digest input engine))))

(defn skein-256
  "Skein cryptographic hash function with fixed output
  digest size to 256."
  [input]
  (skein input 32 32))

(defn skein-512
  "Skein cryptographic hash function with fixed output
  digest size to 256."
  [input]
  (skein input 64 64))

(defn skein-1024
  "Skein cryptographic hash function with fixed output
  digest size to 256."
  [input]
  (skein input 128 128))

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
  [input]
  (digest input :sha1))

(defn md5
  [input]
  (digest input :md5))

(defn whirlpool
  [input]
  (digest input :whirlpool))

(defn ripemd128
  [input]
  (digest input :ripemd128))

(defn ripemd160
  [input]
  (digest input :ripemd160))

(defn ripemd256
  [input]
  (digest input :ripemd256))

(defn ripemd320
  [input]
  (digest input :ripemd320))
