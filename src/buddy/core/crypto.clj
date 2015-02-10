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

(ns buddy.core.crypto
  "Modes implementation"
  (:require [buddy.core.bytes :as bytes]
            [buddy.core.codecs :as codecs])
  (:import org.bouncycastle.crypto.engines.TwofishEngine
           org.bouncycastle.crypto.engines.BlowfishEngine
           org.bouncycastle.crypto.engines.AESEngine
           org.bouncycastle.crypto.engines.ChaChaEngine
           org.bouncycastle.crypto.modes.CBCBlockCipher
           org.bouncycastle.crypto.modes.SICBlockCipher
           org.bouncycastle.crypto.modes.OFBBlockCipher
           org.bouncycastle.crypto.params.ParametersWithIV
           org.bouncycastle.crypto.params.KeyParameter
           clojure.lang.IFn
           clojure.lang.Keyword))


(def ^{:doc "Supported block cipher modes."
       :dynamic true}
  *supported-modes* {:ecb #(identity %)
                     :cbc #(CBCBlockCipher. %)
                     :ctr #(SICBlockCipher. %)
                     :sic #(SICBlockCipher. %)
                     :ofb #(OFBBlockCipher. %1 (* 8 (.getBlockSize %1)))})

(def ^{:doc "Supported block ciphers."
       :dynamic true}
  *supported-block-ciphers* {:twofish #(TwofishEngine.)
                             :blowfish #(BlowfishEngine.)
                             :aes #(AESEngine.)})

(def ^{:doc "Supported block ciphers."
       :dynamic true}
  *supported-stream-ciphers* {:chacha #(ChaChaEngine.)})


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Cipher protocol declaration.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol BlockCipher
  "Common interface to block ciphers."
  (get-block-size [_] "Get block size in bytes."))

(defprotocol StreamCipher
  "Common interface to stream ciphers.")

(defprotocol Cipher
  "Common interface to both, stream and block ciphers."
  (initialize! [_ params] "Initialize cipher")
  (process-block! [_ input] "Encrypt/Decrypt a block of bytes."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^{:private true
       :doc "Check if op is a valid op keyword."
       :static true}
  valid-op? (comp boolean #{:encrypt :decrypt}))

(defn- initialize-cipher!
  [engine {:keys [iv key op]}]
  {:pre [(bytes/bytes? key)
         (valid-op? op)]}
  (let [params (if (nil? iv)
                 (KeyParameter. key)
                 (ParametersWithIV. (KeyParameter. key) iv))
        encrypt (condp = op
                  :encrypt true
                  :decrypt false)]
    (.init engine encrypt params)
    engine))

(defn- block-cipher-process!
  [engine input]
  (let [buffer (byte-array (.getBlockSize engine))]
    (.processBlock engine input 0 buffer 0)
    buffer))

(defn- stream-cipher-process!
  [engine input]
  (let [len    (count input)
        buffer (byte-array len)]
    (.processBytes engine input 0 len buffer 0)
    buffer))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Low level api.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn- algorithm-supported?
  [^Keyword type ^Keyword cipher]
  (condp = type
    :block (contains? *supported-block-ciphers* cipher)
    :stream (contains? *supported-stream-ciphers* cipher)))

(defn- mode-supported?
  [^Keyword mode]
  (contains? *supported-modes* mode))

(defn block-cipher
  "Block cipher engine constructor."
  [^Keyword alg ^Keyword mode]
  {:pre [(algorithm-supported? :block alg)
         (mode-supported? mode)]}
  (let [modefactory (get *supported-modes* mode)
        enginefactory (get *supported-block-ciphers* alg)
        engine (modefactory (enginefactory))]
    (reify
      BlockCipher
      (get-block-size [_]
        (.getBlockSize engine))

      Cipher
      (initialize! [_ params]
        (initialize-cipher! engine params))
      (process-block! [_ input]
        (block-cipher-process! engine input)))))

(defn stream-cipher
  "Stream cipher engine constructor."
  [^Keyword alg]
  {:pre [(algorithm-supported? :stream alg)]}
  (let [enginefactory (get *supported-stream-ciphers* alg)
        engine (enginefactory)]
    (reify
      StreamCipher ;; Mark only
      Cipher
      (initialize! [_ params]
        (initialize-cipher! engine params))
      (process-block! [_ input]
        (stream-cipher-process! engine input)))))

(defn process-bytes!
  "Backward compatibility alias for `process-block!`
  function. This function will be removed in the
  next stable version."
  [engine input]
  (process-block! engine input))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High level api.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn split-by-blocksize
  "Split a byte array in blocksize blocks.

  Given a arbitrary size bytearray and block size in bytes,
  returns a lazy sequence of bytearray blocks of blocksize
  size. If last block does not have enought data for fill
  all block, it is padded using zerobyte padding."
  [^bytes input ^long blocksize]
  (let [inputsize (count input)
        seqgen (fn seqgen [& {:keys [cursormin cursormax remain]}]
                 (cond
                   (<= remain blocksize)
                   (let [buffer (byte-array blocksize)]
                     (System/arraycopy input cursormin buffer 0 remain)
                     (list buffer))

                   (> remain blocksize)
                   (let [buffer (byte-array blocksize)]
                     (System/arraycopy input cursormin buffer 0 blocksize)
                     (cons buffer (lazy-seq (seqgen :cursormin cursormax
                                                    :cursormax (+ cursormax blocksize)
                                                    :remain (- inputsize cursormax)))))
                   :else nil))]
    (lazy-seq (seqgen :cursormin 0
                      :cursormax blocksize
                      :remain inputsize))))

(defn encrypt
  "Encrypt message, and return a result as byte array."
  [input & {:keys [alg mode iv nonce key] :or {alg :aes mode :ctr}}]
  {:pre [(or (bytes/bytes? iv)
             (bytes/bytes? nonce))
         (bytes/bytes? key)]}
  (let [^bytes iv (or iv nonce)
        ^bytes input (codecs/->byte-array input)]
    (cond
      (algorithm-supported? :block alg)
      (let [cipher (block-cipher alg mode)
            blocksize (get-block-size cipher)]
        (initialize! cipher {:op :encrypt :iv iv :key key})
        (apply bytes/concat (reduce (fn [acc block]
                                      (conj acc (process-block! cipher block)))
                                    [] (split-by-blocksize input blocksize))))

      (algorithm-supported? :stream alg)
      (let [cipher (stream-cipher alg)]
        (initialize! cipher {:op :encrypt :iv iv :key key})
        (process-block! cipher input)))))
