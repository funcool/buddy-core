;; Copyright (c) 2013-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.mac
  "Message Authentication Code algorithms."
  (:refer-clojure :exclude [hash reset!])
  (:require [buddy.core.codecs :refer :all]
            [buddy.core.hash :as hash]
            [buddy.core.bytes :as bytes]
            [clojure.java.io :as io])
  (:import
   org.bouncycastle.crypto.Mac
   org.bouncycastle.crypto.BlockCipher
   org.bouncycastle.crypto.digests.SHA256Digest
   org.bouncycastle.crypto.digests.SHA3Digest
   org.bouncycastle.crypto.digests.Blake2bDigest
   org.bouncycastle.crypto.generators.Poly1305KeyGenerator
   org.bouncycastle.crypto.engines.AESFastEngine
   org.bouncycastle.crypto.engines.SerpentEngine
   org.bouncycastle.crypto.engines.TwofishEngine
   org.bouncycastle.crypto.params.KeyParameter
   org.bouncycastle.crypto.params.ParametersWithIV
   org.bouncycastle.crypto.macs.HMac
   org.bouncycastle.crypto.macs.Poly1305))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Abstraction
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IMac
  (-hash [_ engine] "Generate the auth message code")
  (-verify [_ sig engine] "Verify the auth message code"))

(defprotocol IEngineInit
  (-init [_ options] "Initialize the mac"))

(defprotocol IEngine
  (-reset [_] "Reset engine state")
  (-update [_ input offset length] "Update the engine state.")
  (-end [_] "Generates the mac"))

(defmulti ^:no-doc engine
  "A engine constructor."
  :alg)

(def ^:no-doc ^:static
  +cipher-engines+
  {:aes     #(AESFastEngine.)
   :serpent #(SerpentEngine.)
   :twofish #(TwofishEngine.)})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Impl
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn resolve-cipher-engine
  "Given dynamic type engine, try resolve it to
  valid engine instance. By default accepts keywords
  and functions."
  [engine]
  (cond
    (keyword? engine)
    (when-let [factory (get +cipher-engines+ engine)]
      (factory))
    (instance? BlockCipher engine) engine
    (fn? engine) (engine)))

(defn- key->polykey
  "Noramalizes 32 bytes array key to poly1305
  formatted byte array key."
  [^bytes key]
  (let [key (bytes/copy key)]
    (Poly1305KeyGenerator/clamp key)
    key))

(extend-type Mac
  IEngineInit
  (-init [it options]
    (let [key (:key options)
          keyparam (KeyParameter. (to-bytes key))]
      (.init it keyparam)))

  IEngine
  (-reset [it]
    (.reset it))
  (-update [it input offset length]
    (.update it input offset length))
  (-end [it]
    (let [buffer (byte-array (.getMacSize it))]
      (.doFinal it buffer 0)
      buffer)))

(extend-type Poly1305
  IEngineInit
  (-init [it options]
    (let [key (to-bytes (:key options))
          iv (to-bytes (:iv options))]
      (assert (= (count iv) 16) "Wrong iv length (should be 16 bytes)")
      (assert (= (count key) 32) "Wrong key length (should be 32 bytes)")
      (let [params (KeyParameter. (key->polykey key))
            params (ParametersWithIV. params iv)]
        (.init it params)))))

(defmethod engine :hmac
  [options]
  (let [digest (hash/resolve-digest-engine
                (:digest options :sha256))]
    (assert digest "Invalid digest engine.")
    (HMac. digest)))

(defmethod engine :hmac+sha1
  [options]
  (let [digest (hash/resolve-digest-engine :sha1)]
    (HMac. digest)))

(defmethod engine :hmac+sha256
  [options]
  (let [digest (hash/resolve-digest-engine :sha256)]
    (HMac. digest)))

(defmethod engine :hmac+sha384
  [options]
  (let [digest (hash/resolve-digest-engine :sha384)]
    (HMac. digest)))

(defmethod engine :hmac+sha512
  [options]
  (let [digest (hash/resolve-digest-engine :sha512)]
    (HMac. digest)))

(defmethod engine :poly1305
  [options]
  (let [cipher (resolve-cipher-engine
                (:cipher options :aes))]
    (assert cipher "Invalid cipher engine.")
    (Poly1305. cipher)))

(defmethod engine :poly1305+aes
  [options]
  (let [cipher (resolve-cipher-engine :aes)]
    (Poly1305. cipher)))

(defmethod engine :poly1305+twofish
  [options]
  (let [cipher (resolve-cipher-engine :twofish)]
    (Poly1305. cipher)))

(defmethod engine :poly1305+serpent
  [options]
  (let [cipher (resolve-cipher-engine :serpent)]
    (Poly1305. cipher)))

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

(defn- verify-plain-data
  [^bytes input, ^bytes signature, engine]
  (let [sig (hash-plain-data input engine)]
    (bytes/equals? sig signature)))

(defn- verify-stream
  [^java.io.InputStream input, ^bytes signature, engine]
  (let [sig (hash-stream-data input engine)]
    (bytes/equals? sig signature)))

(extend-protocol IMac
  (Class/forName "[B")
  (-hash [^bytes input engine]
    (hash-plain-data input engine))
  (-verify [^bytes input ^bytes signature engine]
    (verify-plain-data input signature engine))

  java.lang.String
  (-hash [^String input engine]
    (hash-plain-data (to-bytes input) engine))
  (-verify [^String input ^bytes signature engine]
    (verify-plain-data (to-bytes input) signature engine))

  java.io.InputStream
  (-hash [^java.io.InputStream input engine]
    (hash-stream-data input engine))
  (-verify [^java.io.InputStream input ^bytes signature engine]
    (verify-stream input signature engine))

  java.io.File
  (-hash [^java.io.File input engine]
    (hash-stream-data (io/input-stream input) engine))
  (-verify [^java.io.File input ^bytes signature engine]
    (verify-stream (io/input-stream input) signature engine))

  java.net.URL
  (-hash [^java.net.URL input engine]
    (hash-stream-data (io/input-stream input) engine))
  (-verify [^java.net.URL input ^bytes signature engine]
    (verify-stream (io/input-stream input) signature engine))

  java.net.URI
  (-hash [^java.net.URI input engine]
    (hash-stream-data (io/input-stream input) engine))
  (-verify [^java.net.URI input ^bytes signature engine]
    (verify-stream (io/input-stream input) signature engine)))

(defn hash
  "Generate hmac digest for arbitrary
  input data, a secret key and hash algorithm.

  If algorithm is not supplied, sha256
  will be used as default value."
  [input engine-or-options]
  (if (satisfies? IEngine engine-or-options)
    (-hash input engine-or-options)
    (let [engine (engine engine-or-options)]
      (-init engine engine-or-options)
      (-hash input engine))))

(defn verify
  "Verify hmac for artbitrary input and signature."
  [input signature engine-or-options]
  (let [signature (to-bytes signature)]
    (if (satisfies? IEngine engine-or-options)
      (-verify input signature engine-or-options)
      (let [engine (engine engine-or-options)]
        (-init engine engine-or-options)
        (-verify input signature engine)))))
