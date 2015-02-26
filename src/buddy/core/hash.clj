;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.be>
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
   :sha3-384 #(SHA3Digest. 284)
   :sha3-512 #(SHA3Digest. 512)})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocol definitions (abstractions)
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IDigest
  (^:private digest* [input algorithm] "Low level interface, always returns bytes"))

(defprotocol IHash
  "Mac engine common interface definition."
  (^:private update [_ bytes offset length] "Update bytes in a current instance.")
  (^:private end [_] "Return the computed mac and reset the engine."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn update!
  ([engine input]
   (update engine input 0 (count input)))
  ([engine input offset]
   (update engine input offset (count input)))
  ([engine input offset length]
   (update engine input offset length)))

(defn end!
  [engine]
  (end engine))

(defn resolve-digest
  "Helper function for make Digest instances
  from algorithm parameter."
  [alg]
  (cond
   (instance? Keyword alg) (let [factory (*available-digests* alg)]
                             (factory))
   (instance? IFn alg) (alg)
   (instance? Digest alg) alg))

(defn hash-engine
  "Create a hash engine instance."
  [^Keyword alg]
  (let [engine (resolve-digest alg)]
    (reify
      IHash
      (update [_ input offset length]
        (.update engine input offset length))
      (end [_]
        (let [buffer (byte-array (.getDigestSize engine))]
          (.doFinal engine buffer 0)
          buffer)))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details for different data types.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- hash-plain-data
  [^bytes input ^Keyword alg]
  (let [engine (hash-engine alg)]
    (update! engine input)
    (end! engine)))

(defn- hash-stream-data
  [^java.io.InputStream input ^Keyword alg]
  (let [engine (hash-engine alg)
        buffer (byte-array 5120)]
    (loop []
      (let [readed (.read input buffer 0 5120)]
        (when-not (= readed -1)
          (update! engine buffer 0 readed)
          (recur))))
    (end! engine)))

(extend-protocol IDigest
  (Class/forName "[B")
  (digest* [^bytes input ^Keyword alg]
    (hash-plain-data input alg))

  String
  (digest* [^String input ^Keyword alg]
    (hash-plain-data (str->bytes input) alg))

  java.io.InputStream
  (digest* [^java.io.InputStream input ^Keyword alg]
    (hash-stream-data input alg))

  java.io.File
  (digest* [^java.io.File input ^Keyword alg]
    (hash-stream-data (io/input-stream input) alg))

  java.net.URL
  (digest* [^java.net.URL input ^Keyword alg]
    (hash-stream-data (io/input-stream input) alg))

  java.net.URI
  (digest* [^java.net.URI input ^Keyword alg]
    (hash-stream-data (io/input-stream input) alg)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level public api.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn digest
  "Generic function for create cryptographic hash."
  [input ^Keyword alg]
  (digest* input alg))

(def sha256 #(digest % :sha256))
(def sha384 #(digest % :sha384))
(def sha512 #(digest % :sha512))
(def sha3-256 #(digest % :sha3-256))
(def sha3-384 #(digest % :sha3-384))
(def sha3-512 #(digest % :sha3-512))
(def sha1 #(digest % :sha1))
(def md5 #(digest % :md5))
