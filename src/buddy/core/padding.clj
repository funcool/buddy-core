;; Copyright (c) 2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.core.padding
  "Block padding algorithms."
  (:require [buddy.core.bytes :as bytes])
  (:import org.bouncycastle.crypto.paddings.ZeroBytePadding
           org.bouncycastle.crypto.paddings.X923Padding
           org.bouncycastle.crypto.paddings.PKCS7Padding
           org.bouncycastle.crypto.paddings.TBCPadding
           org.bouncycastle.crypto.paddings.ISO7816d4Padding
           org.bouncycastle.crypto.paddings.ISO10126d2Padding
           clojure.lang.Keyword))

(defn padding-engine
  "Create a padding enginde for given algorithm name."
  [^Keyword alg]
  (condp = alg
    :zerobyte (ZeroBytePadding.)
    :pkcs7 (PKCS7Padding.)
    :tbc (TBCPadding.)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level api.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn pad!
  "Add padding using one of supported padding algorithms."
  ([^bytes input ^long offset] (pad input offset :zerobyte))
  ([^bytes input ^long offset ^Keyword alg]
   (let [engine (padding-engine alg)]
     (.init engine (java.security.SecureRandom.))
     (.addPadding engine input offset))))

(defn pad
  "Add padding using one of supported padding algorithms.
  This is a side effect free version of pad! function."
  ([^bytes input ^long offset] (pad input offset :zerobyte))
  ([^bytes input ^long offset ^Keyword alg]
   (let [^bytes input (bytes/copy input)]
     (pad! input offset alg)
     input)))

(defn padded?
  "Check if given byte array has padding using specified
  padding algorithm. If no one is specified, :zerobyte
  will be used."
  ([^bytes input] (padded? input :zerobyte))
  ([^bytes input ^Keyword alg]
   (let [engine (padding-engine alg)]
     (pos? (.padCount engine input)))))

(defn unpad
  "Remove padding from given byte array and return a new
  byte array without padding."
  ([^bytes input] (unpad input :zerobyte))
  ([^bytes input ^Keyword alg]
   (let [engine (padding-engine alg)
         num (.padCount engine input)]
     (bytes/slice input 0 (- (count input) num)))))
