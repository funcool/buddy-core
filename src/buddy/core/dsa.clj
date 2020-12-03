;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.dsa
  "Digital Signature Algorithms."
  (:refer-clojure :exclude [resolve])
  (:require [buddy.core.codecs :refer :all]
            [clojure.java.io :as io])
  (:import java.security.PublicKey
           java.security.PrivateKey
           java.security.Signature
           java.security.Security))

(when (nil? (Security/getProvider "BC"))
  (Security/addProvider (org.bouncycastle.jce.provider.BouncyCastleProvider.)))

(def ^:no-doc
  +algorithms+
  {:rsassa-pss+sha256    #(Signature/getInstance "SHA256withRSAandMGF1" "BC")
   :rsassa-pss+sha384    #(Signature/getInstance "SHA384withRSAandMGF1" "BC")
   :rsassa-pss+sha512    #(Signature/getInstance "SHA512withRSAandMGF1" "BC")
   :rsassa-pkcs15+sha256 #(Signature/getInstance "SHA256withRSA" "BC")
   :rsassa-pkcs15+sha384 #(Signature/getInstance "SHA384withRSA" "BC")
   :rsassa-pkcs15+sha512 #(Signature/getInstance "SHA512withRSA" "BC")
   :ecdsa+sha256         #(Signature/getInstance "SHA256withECDSA" "BC")
   :ecdsa+sha384         #(Signature/getInstance "SHA384withECDSA" "BC")
   :ecdsa+sha512         #(Signature/getInstance "SHA512withECDSA" "BC")
   :eddsa                #(Signature/getInstance "EDDSA" "BC")})

(def ^:no-doc ^:static
  +buffer-size+ 5120)

(defprotocol IEngine
  (-init [_ options] "Initialize signature.")
  (-update [_ input offset length] "Update signature state.")
  (-end [_ signature?] "Returns the computed signature."))

(defprotocol ISignature
  "Default inteterface for all signature
  algorithms supported by `buddy`."
  (-sign [input engine] "Make signature.")
  (-verify [input signature engine] "Verify signature."))

(defn- resolve
  "Given dynamic type engine, try resolve it to
  valid engine instance. By default accepts keywords
  and functions."
  [signer]
  (cond
    (keyword? signer)
    (when-let [factory (get +algorithms+ signer)]
      (factory))
    (fn? signer)
    (signer)))

(extend-protocol IEngine
  Signature
  (-init [^Signature it options]
    (let [verify? (:verify options false)
          ^PublicKey key (:key options)]
      (if verify?
        (.initVerify it key)
        (let [prng (or (:prng options)
                       (java.security.SecureRandom.))]
          (.initSign it key prng)))))

  (-update [it input offset length]
    (.update it input offset length))

  (-end [it signature?]
    (if signature?
      (.verify it signature?)
      (.sign it))))

(defn- make-signature-for-plain-data
  [^bytes input engine]
  (-update engine input 0 (count input))
  (-end engine nil))

(defn- verify-signature-for-plain-data
  [^bytes input, ^bytes signature, engine]
  (-update engine input 0 (count input))
  (-end engine signature))

(defn- make-signature-for-stream
  [^java.io.InputStream stream engine]
  (let [buff (byte-array +buffer-size+)]
    (loop []
      (let [readed (.read stream buff 0 +buffer-size+)]
        (when-not (= readed -1)
          (-update engine buff 0 readed)
          (recur))))
    (-end engine nil)))

(defn- verify-signature-for-stream
  [^java.io.InputStream stream, ^bytes signature, engine]
  (let [buff (byte-array +buffer-size+)]
    (loop []
      (let [readed (.read stream buff 0 +buffer-size+)]
        (when-not (= readed -1)
          (-update engine buff 0 readed)
          (recur))))
    (-end engine signature)))

(extend-protocol ISignature
  (Class/forName "[B")
  (-sign [^bytes input engine]
    (make-signature-for-plain-data input engine))
  (-verify [^bytes input, ^bytes signature, engine]
    (verify-signature-for-plain-data input signature engine))

  java.lang.String
  (-sign [^String input, engine]
    (make-signature-for-plain-data (to-bytes input) engine))
  (-verify [^String input, ^bytes signature, engine]
    (verify-signature-for-plain-data (to-bytes input) signature engine))

  java.io.InputStream
  (-sign [^java.io.InputStream input, engine]
    (make-signature-for-stream input engine))
  (-verify [^java.io.InputInput input, ^bytes signature, engine]
    (verify-signature-for-stream input signature engine))

  java.io.File
  (-sign [^java.io.File input, engine]
    (make-signature-for-stream (io/input-stream input) engine))
  (-verify [^java.io.File input, ^bytes signature, engine]
    (verify-signature-for-stream (io/input-stream input) signature engine))

  java.net.URL
  (-sign [^java.net.URL input, engine]
    (make-signature-for-stream (io/input-stream input) engine))
  (-verify [^java.net.URL input, ^bytes signature, engine]
    (verify-signature-for-stream (io/input-stream input) signature engine))

  java.net.URI
  (-sign [^java.net.URI input, engine]
    (make-signature-for-stream (io/input-stream input) engine))
  (-verify [^java.net.URI input, ^bytes signature, engine]
    (verify-signature-for-stream (io/input-stream input) signature engine)))

(defn sign
  [input {:keys [alg key prng]}]
  (let [engine (resolve alg)]
    (-init engine {:verify false :key key :prng prng})
    (-sign input engine)))

(defn verify
  [input signature {:keys [key alg]}]
  (let [engine (resolve alg)]
    (-init engine {:verify true :key key})
    (-verify input signature engine)))



