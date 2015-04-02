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
           org.bouncycastle.crypto.modes.GCMBlockCipher
           org.bouncycastle.crypto.modes.AEADBlockCipher
           org.bouncycastle.crypto.params.ParametersWithIV
           org.bouncycastle.crypto.params.AEADParameters
           org.bouncycastle.crypto.params.KeyParameter
           org.bouncycastle.crypto.BlockCipher
           org.bouncycastle.crypto.StreamCipher
           clojure.lang.IFn
           clojure.lang.Keyword))

(def ^{:doc "Supported block cipher modes."
       :dynamic true}
  *supported-modes* {:ecb #(identity %)
                     :cbc #(CBCBlockCipher. %)
                     :gcm #(GCMBlockCipher. %)
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

(defprotocol IBlockCipher
  "Common protocol to block ciphers."
  (^:private get-block-size* [_] "Get block size in bytes."))

(defprotocol IStreamCipher
  "Common protocol to stream ciphers.")

(defprotocol ICipher
  "Common protocol to both, stream and block ciphers."
  (^:private initialize [_ params] "Initialize cipher")
  (^:private process-bytes [_ input] [_ input inoffset output outoffset]
    "Encrypt/Decrypt a block of bytes."))

(defprotocol IAEADBlockCipher
  "Common protocol to Authenticated Cipher."
  (^:private calculate-authtag [_ output outoffset] "Calculate the authentication tag.")
  (^:private get-output-size* [_ data] "Get the output size."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-type StreamCipher
  IStreamCipher
  ICipher
  (initialize [engine params]
    (let [iv (:iv params)
          key (:key params)
          params' (if (nil? iv)
                    (KeyParameter. key)
                    (ParametersWithIV. (KeyParameter. key) iv))
          encrypt (condp = (:op params)
                    :encrypt true
                    :decrypt false)]
      (.init engine encrypt params')
      engine))

  (process-bytes
    ([engine input]
     (let [len    (count input)
           buffer (byte-array len)]
       (.processBytes engine input 0 len buffer 0)
       buffer))
    ([engine input inoffset output outoffset]
     (.processBytes engine input inoffset output outoffset))))

(extend-type BlockCipher
  IBlockCipher
  (get-block-size* [engine]
    (.getBlockSize engine))

  ICipher
  (initialize [engine params]
    (let [iv (:iv params)
          key (:key params)
          params' (if (nil? iv)
                    (KeyParameter. key)
                    (ParametersWithIV. (KeyParameter. key) iv))
          encrypt (condp = (:op params)
                    :encrypt true
                    :decrypt false)]
      (.init engine encrypt params')
      engine))

  (process-bytes
    ([engine input]
     (let [buffer (byte-array (get-block-size* engine))]
       (.processBlock engine input 0 buffer 0)
       buffer))
    ([engine input inoffset output outoffset]
     (.processBlock engine input inoffset output outoffset))))

(extend-type AEADBlockCipher
  IAEADBlockCipher
  (get-output-size* [engine length]
    (.getOutputSize engine length))

  (calculate-authtag [engine output outoffset]
    (.doFinal engine output outoffset))

  IBlockCipher
  (get-block-size* [engine]
    (get-block-size* (.getUnderlyingCipher engine)))

  ICipher
  (initialize [engine params]
    (let [iv (:iv params)
          key (:key params)
          aad (:aad params)
          tagsize (:authtag-size params 128)
          keyparam (KeyParameter. key)
          params' (AEADParameters. keyparam tagsize iv aad)
          encrypt (condp = (:op params :encrypt)
                    :encrypt true
                    :decrypt false)]
      (.init engine encrypt params')
      engine))

  (process-bytes
    ([engine input]
     (let [buffer (byte-array (get-block-size* engine))]
       (.processBytes engine input 0 buffer 0)
       buffer))

    ([engine input inoffset output outoffset]
     (let [length (count input)]
       (.processBytes engine input inoffset length output outoffset)))))

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

(defn get-block-size
  "Given a block cipher, return the block size
  in bytes."
  [^BlockCipher engine]
  (get-block-size* engine))

(defn get-output-size
  "Given a aead cipher, return the buffer size required for
  a `process-bytes!` plus a `calculate-authtag!` with an input of
  `len` bytes."
  [^AEADBlockCipher engine ^long len]
  (get-output-size* engine len))

(defn block-cipher
  "Block cipher engine constructor."
  [^Keyword alg ^Keyword mode]
  {:pre [(algorithm-supported? :block alg)
         (mode-supported? mode)]}
  (let [modefactory (get *supported-modes* mode)
        enginefactory (get *supported-block-ciphers* alg)]
    (modefactory (enginefactory))))

(defn stream-cipher
  "Stream cipher engine constructor."
  [^Keyword alg]
  {:pre [(algorithm-supported? :stream alg)]}
  (let [enginefactory (get *supported-stream-ciphers* alg)]
    (enginefactory)))

(defn initialize!
  "Initialize the cipher engine."
  [engine {:keys [iv key op] :as params}]
  (initialize engine params))

(defn process-bytes!
  "Encrypt or decrypt a block of bytes using the specified engine.
  The length of the block to encrypt or decrypt depends on the used
  crypto engine. A great example are stream cipher engine
  that allows blocks of 1 byte lenght."
  ([engine input]
   (process-bytes engine input))
  ([engine input inoffset output outoffset]
   (process-bytes engine input inoffset output outoffset)))

(defn process-block!
  "Encrypt or decrypt a block of bytes using the specified engine.
  The length of the block to encrypt or decrypt depends on the used
  crypto engine. A great example are stream cipher engine
  that allows blocks of 1 byte lenght.
  This is an alias to `process-bytes! function."
  ([engine input]
   (process-bytes engine input))
  ([engine input inoffset output outoffset]
   (process-bytes engine input inoffset output outoffset)))

(defn calculate-authtag!
  [engine output offset]
  (calculate-authtag engine output offset))

(defn- split-by-blocksize
  "Split a byte array in blocksize blocks.
  Given a arbitrary size bytearray and block size in bytes,
  returns a lazy sequence of bytearray blocks of blocksize
  size. If last block does not have enought data for fill
  all block, it is padded using zerobyte padding."
  ([^bytes input ^long blocksize]
   (split-by-blocksize input blocksize false))
  ([^bytes input ^long blocksize additional]
   (let [inputsize (count input)]
     (loop [cursormin 0
            cursormax blocksize
            remain inputsize
            result []]
       (cond
         (= remain 0)
         (if additional
           (conj result (byte-array blocksize))
           result)

         (< remain blocksize)
         (let [buffer (byte-array blocksize)]
           (System/arraycopy input cursormin buffer 0 remain)
           (conj result buffer))

         (>= remain blocksize)
         (let [buffer (byte-array blocksize)]
           (System/arraycopy input cursormin buffer 0 blocksize)
           (recur cursormax
                  (+ cursormax blocksize)
                  (- inputsize cursormax)
                  (conj result buffer))))))))
