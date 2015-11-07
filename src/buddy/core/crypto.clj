;; Copyright (c) 2013-2015 Andrey Antukh <niwi@niwi.nz>
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
  "Crypto engines low-level abstraction."
  (:require [buddy.core.bytes :as bytes]
            [buddy.core.padding :as padding]
            [buddy.core.mac :as mac]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs])
  (:import org.bouncycastle.crypto.engines.TwofishEngine
           org.bouncycastle.crypto.engines.SerpentEngine
           org.bouncycastle.crypto.engines.BlowfishEngine
           org.bouncycastle.crypto.engines.AESFastEngine
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
           org.bouncycastle.crypto.InvalidCipherTextException
           java.nio.ByteBuffer
           clojure.lang.IFn
           clojure.lang.Keyword))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Protocols
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(def ^:no-doc
  +block-cipher-engines+
  {:aes     #(AESFastEngine.)
   :serpent #(SerpentEngine.)
   :twofish #(TwofishEngine.)})

(def ^:no-doc
  +stream-cipher-engines+
  {:chacha #(ChaChaEngine.)})

(def ^{:doc false}
  +cipher-modes+
  {:ecb #(identity %)
   :cbc #(CBCBlockCipher. %)
   :gcm #(GCMBlockCipher. %)
   :ctr #(SICBlockCipher. %)
   :sic #(SICBlockCipher. %)
   :ofb #(OFBBlockCipher. % (* 8 (.getBlockSize %)))})

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Cipher protocol declaration.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defprotocol IBlockCipher
  "Common protocol to block ciphers."
  (-block-size [_] "Get block size in bytes."))

(defprotocol IStreamCipher
  "Common protocol to stream ciphers.")

(defprotocol ICipher
  "Common protocol to both, stream and block ciphers."
  (-init [_ params] "Initialize cipher")
  (-process-bytes [_ input] [_ input inoffset output outoffset]
    "Encrypt/Decrypt a block of bytes."))

(defprotocol IAEADBlockCipher
  "Common protocol to Authenticated Cipher."
  (-auth-tag [_ output outoffset] "Calculate the authentication tag.")
  (-output-size [_ data] "Get the output size."))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Implementation details.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(extend-type StreamCipher
  IStreamCipher
  ICipher
  (-init [engine params]
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

  (-process-bytes
    ([engine input]
     (let [len    (count input)
           buffer (byte-array len)]
       (.processBytes engine input 0 len buffer 0)
       buffer))
    ([engine input inoffset output outoffset]
     (.processBytes engine input inoffset output outoffset))))

(extend-type BlockCipher
  IBlockCipher
  (-block-size [engine]
    (.getBlockSize engine))

  ICipher
  (-init [engine params]
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

  (-process-bytes
    ([engine input]
     (let [buffer (byte-array (-block-size engine))]
       (.processBlock engine input 0 buffer 0)
       buffer))
    ([engine input inoffset output outoffset]
     (.processBlock engine input inoffset output outoffset))))

(extend-type AEADBlockCipher
  IAEADBlockCipher
  (-output-size [engine length]
    (.getOutputSize engine length))

  (-auth-tag [engine output outoffset]
    (.doFinal engine output outoffset))

  IBlockCipher
  (-block-size [engine]
    (-block-size (.getUnderlyingCipher engine)))

  ICipher
  (-init [engine params]
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

  (-process-bytes
    ([engine input]
     (let [buffer (byte-array (-block-size engine))]
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
    :block (contains? +block-cipher-engines+ cipher)
    :stream (contains? +stream-cipher-engines+ cipher)))

(defn- mode-supported?
  [mode]
  (contains? +cipher-modes+ mode))

(defn get-block-size
  "Given a block cipher, return the block size
  in bytes."
  [engine]
  (-block-size engine))

(defn get-output-size
  "Given a aead cipher, return the buffer size required for
  a `process-bytes!` plus a `calculate-authtag!` with an input of
  `len` bytes."
  [engine len]
  (-output-size engine len))

(defn block-cipher
  "Block cipher engine constructor."
  [alg mode]
  {:pre [(algorithm-supported? :block alg)
         (mode-supported? mode)]}
  (let [modefactory (get +cipher-modes+ mode)
        enginefactory (get +block-cipher-engines+ alg)]
    (modefactory (enginefactory))))

(defn stream-cipher
  "Stream cipher engine constructor."
  [^Keyword alg]
  {:pre [(algorithm-supported? :stream alg)]}
  (let [enginefactory (get +stream-cipher-engines+ alg)]
    (enginefactory)))

(defn initialize!
  "Initialize the cipher engine."
  [engine {:keys [iv key op] :as params}]
  (-init engine params))

(defn process-bytes!
  "Encrypt or decrypt a block of bytes using the specified engine.
  The length of the block to encrypt or decrypt depends on the used
  crypto engine. A great example are stream cipher engine
  that allows blocks of 1 byte lenght."
  ([engine input]
   (-process-bytes engine input))
  ([engine input inoffset output outoffset]
   (-process-bytes engine input inoffset output outoffset)))

(defn process-block!
  "Encrypt or decrypt a block of bytes using the specified engine.
  The length of the block to encrypt or decrypt depends on the used
  crypto engine. A great example are stream cipher engine
  that allows blocks of 1 byte lenght.
  This is an alias to `process-bytes! function."
  ([engine input]
   (-process-bytes engine input))
  ([engine input inoffset output outoffset]
   (-process-bytes engine input inoffset output outoffset)))

(defn calculate-authtag!
  [engine output offset]
  (-auth-tag engine output offset))

(defn split-by-blocksize
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High-Level Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05

(def ^:private keylength? #(= (count %1) %2))
(def ^:private ivlength? #(= (count %1) %2))

(defn- encrypt-cbc
  [cipher input key iv]
  (let [blocksize (get-block-size cipher)
        blocks (split-by-blocksize input blocksize true)
        inputsize (count input)]
    (initialize! cipher {:op :encrypt :iv iv :key key})
    (apply bytes/concat
           (loop [blocks blocks
                  processed []
                  pos 0]
             (let [block (first blocks)
                   last? (empty? (rest blocks))]
               (if-not last?
                 (recur (rest blocks)
                        (conj processed (process-block! cipher block))
                        (+ pos (count block)))
                 (let [remaining (- inputsize pos)]
                   (padding/pad! block remaining :pkcs7)
                   (conj processed (process-block! cipher block)))))))))

(defn- decrypt-cbc
  [cipher input key iv]
  (let [blocksize (get-block-size cipher)
        blocks (split-by-blocksize input blocksize false)]
    (initialize! cipher {:op :decrypt :iv iv :key key})
    (apply bytes/concat
           (loop [blocks blocks
                  processed []]
             (let [block (process-block! cipher (first blocks))
                   last? (empty? (rest blocks))]
               (if-not last?
                 (recur (rest blocks)
                        (conj processed block))
                 (let [result (padding/unpad block :pkcs7)]
                   (conj processed result))))))))

(defn- encrypt-gcm
  [cipher input key iv aad]
  (initialize! cipher {:iv iv :key key :tagsize 128 :op :encrypt :aad aad})
  (let [outputlength (get-output-size cipher (count input))
        output (byte-array outputlength)
        offset (process-block! cipher input 0 output 0)]
    (try
      (calculate-authtag! cipher output offset)
      (catch InvalidCipherTextException e
        (let [message (str "Couldn't generate gcm authentication tag: "
                           (.getMessage e))]
          (throw (ex-info message {:type :encryption :cause :authtag})))))
    output))

(defn- decrypt-gcm
  [cipher ciphertext key iv aad]
  (initialize! cipher {:iv iv :key key :tagsize 128 :op :decrypt :aad aad})
  (let [input (bytes/copy ciphertext)
        inputlength (count ciphertext)
        outputlength (get-output-size cipher inputlength)
        output (byte-array outputlength)
        offset (process-block! cipher input 0 output 0)]
    (try
      (calculate-authtag! cipher output offset)
      (catch InvalidCipherTextException e
        (let [message (str "Couldn't validate gcm authentication tag: "
                           (.getMessage e))]
          (throw (ex-info message {:type :validation :cause :authtag})))))
    output))

(defn- aad->bytes
  [aad]
  (let [length (* (count aad) 8)
        buffer (ByteBuffer/allocate 8)]
    (.putLong buffer length)
    (.array buffer)))

(defn- extract-encryption-key
  [key algorithm]
  {:pre [(bytes/bytes? key)]}
  (case algorithm
    :aes128-cbc-hmac-sha256 (bytes/slice key 16 32)
    :aes192-cbc-hmac-sha384 (bytes/slice key 24 48)
    :aes256-cbc-hmac-sha512 (bytes/slice key 32 64)))

(defn- extract-authentication-key
  [key algorithm]
  {:pre [(bytes/bytes? key)]}
  (case algorithm
    :aes128-cbc-hmac-sha256 (bytes/slice key 0 16)
    :aes192-cbc-hmac-sha384 (bytes/slice key 0 24)
    :aes256-cbc-hmac-sha512 (bytes/slice key 0 32)))

(defn- generate-authtag
  [{:keys [algorithm input authkey iv aad] :as params}]
  (let [al (if aad
             (aad->bytes aad)
             (byte-array 0))
        data (bytes/concat aad iv input al)
        fulltag (mac/hash data {:key authkey :alg :hmac :digest algorithm})
        truncatesize (quot (count fulltag) 2)]
    (bytes/slice fulltag 0 truncatesize)))

(defn- verify-authtag
  [tag params]
  (let [tag' (generate-authtag params)]
    (bytes/equals? tag tag')))

(defmulti encrypt* :algorithm)
(defmulti decrypt* :algorithm)

(defmethod encrypt* :aes128-cbc-hmac-sha256
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key algorithm)
        authkey (extract-authentication-key key algorithm)
        ciphertext (encrypt-cbc cipher input encryptionkey iv)
        tag (generate-authtag {:algorithm :sha256
                               :input ciphertext
                               :authkey authkey
                               :aad aad
                               :iv iv})]
    (bytes/concat ciphertext tag)))

(defmethod decrypt* :aes128-cbc-hmac-sha256
  [{:keys [algorithm input key iv] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key algorithm)
        authkey (extract-authentication-key key algorithm)
        [ciphertext authtag] (let [inputlen (count input)
                                   taglen (quot 32 2) ciphertext (bytes/slice input 0 (- inputlen taglen))
                                   tag (bytes/slice input (- inputlen taglen) inputlen)]
                               [ciphertext tag])]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :algorithm :sha256 :input ciphertext))
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :authtag})))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod encrypt* :aes192-cbc-hmac-sha384
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 48) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key algorithm)
        authkey (extract-authentication-key key algorithm)
        ciphertext (encrypt-cbc cipher input encryptionkey iv)
        tag (generate-authtag {:algorithm :sha384
                               :input ciphertext
                               :authkey authkey
                               :iv iv
                               :aad aad})]
    (bytes/concat ciphertext tag)))

(defmethod decrypt* :aes192-cbc-hmac-sha384
  [{:keys [algorithm input key iv] :as params}]
  {:pre [(keylength? key 48) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key algorithm)
        authkey (extract-authentication-key key algorithm)
        [ciphertext authtag] (let [inputlen (count input)
                                   taglen (quot 48 2) ciphertext (bytes/slice input 0 (- inputlen taglen))
                                   tag (bytes/slice input (- inputlen taglen) inputlen)]
                               [ciphertext tag])]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :algorithm :sha384 :input ciphertext))
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :authtag})))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod encrypt* :aes256-cbc-hmac-sha512
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 64) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key algorithm)
        authkey (extract-authentication-key key algorithm)
        ciphertext (encrypt-cbc cipher input encryptionkey iv)
        tag (generate-authtag {:algorithm :sha512
                               :input ciphertext
                               :authkey authkey
                               :iv iv
                               :aad aad})]
    (bytes/concat ciphertext tag)))

(defmethod decrypt* :aes256-cbc-hmac-sha512
  [{:keys [algorithm input key iv] :as params}]
  {:pre [(keylength? key 64) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key algorithm)
        authkey (extract-authentication-key key algorithm)
        [ciphertext authtag] (let [inputlen (count input)
                                   taglen (quot 64 2) ciphertext (bytes/slice input 0 (- inputlen taglen))
                                   tag (bytes/slice input (- inputlen taglen) inputlen)]
                               [ciphertext tag])]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :algorithm :sha512 :input ciphertext))
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :authtag})))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod encrypt* :aes128-gcm
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 16) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (encrypt-gcm cipher input key iv aad)))

(defmethod decrypt* :aes128-gcm
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 16) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (decrypt-gcm cipher input key iv aad)))

(defmethod encrypt* :aes192-gcm
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 24) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (encrypt-gcm cipher input key iv aad)))

(defmethod decrypt* :aes192-gcm
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 24) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (decrypt-gcm cipher input key iv aad)))

(defmethod encrypt* :aes256-gcm
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (encrypt-gcm cipher input key iv aad)))

(defmethod decrypt* :aes256-gcm
  [{:keys [algorithm input key iv aad] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (decrypt-gcm cipher input key iv aad)))

(defn encrypt
  "Encrypt arbitrary length data using one of the supported encryption
  scheme. The default encryption scheme is: `:aes128-cbc-hmac-sha256`.

  Example: `(encrypt \"hello world\" mykey myiv)`

  You can specify an other encryption scheme passing an additional
  parameter.

  Example: `(encrypt \"hello world\" mykey myiv {:algorithm :aes128-cbc-hmac-sha512})`

  See the documentation for know the complete list of supported
  encryption schemes.

  The input, key and iv parameters should be of any type
  that can be coerced to byte array."
  ([input key iv]
   (encrypt input key iv {}))
  ([input key iv {:keys [algorithm] :or {algorithm :aes128-cbc-hmac-sha256} :as options}]
   (let [key (codecs/->byte-array key)
         iv  (codecs/->byte-array iv)]
     (encrypt* {:algorithm algorithm :input input :key key :iv iv}))))

(defn decrypt
  "Decrypt data encrypted using the `encrypt` function.

  The input, key and iv parameters should be of any type
  that can be coerced to byte array."
  ([input key iv]
   (decrypt input key iv {}))
  ([input key iv {:keys [algorithm] :or {algorithm :aes128-cbc-hmac-sha256}}]
   (let [key (codecs/->byte-array key)
         iv  (codecs/->byte-array iv)]
     (decrypt* {:algorithm algorithm
                :input input
                :key key
                :iv iv}))))
