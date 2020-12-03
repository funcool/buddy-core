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

(ns buddy.core.crypto
  "Crypto engines low-level abstraction."
  (:require [buddy.core.bytes :as bytes]
            [buddy.core.padding :as padding]
            [buddy.core.mac :as mac]
            [buddy.core.nonce :as nonce]
            [buddy.core.codecs :as codecs])
  (:import
   org.bouncycastle.crypto.engines.TwofishEngine
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

;; --- Constants

(def ^:no-doc
  +block-cipher-engines+
  {:aes     #(AESFastEngine.)
   :serpent #(SerpentEngine.)
   :twofish #(TwofishEngine.)})

(def ^:no-doc
  +stream-cipher-engines+
  {:chacha #(ChaChaEngine.)})

(def ^:no-doc
  +cipher-modes+
  {:ecb #(identity %)
   :cbc #(CBCBlockCipher. %)
   :gcm #(GCMBlockCipher. %)
   :ctr #(SICBlockCipher. %)
   :sic #(SICBlockCipher. %)
   :ofb #(OFBBlockCipher. % (* 8 (.getBlockSize ^BlockCipher %)))})

;; --- Implementation details.

(defn- init-block-cipher
  "A generic implementation for block ciphers initialization process."
  [engine {:keys [iv key op] :or {op :encrypt}}]
  (assert (instance? BlockCipher engine) "Should be block cipher.")
  (let [params (if (nil? iv)
                 (KeyParameter. key)
                 (ParametersWithIV. (KeyParameter. key) iv))
        encrypt? (case op
                   :encrypt true
                   :decrypt false)]
    (.init ^BlockCipher engine encrypt? params)
    engine))

(defn- init-stream-cipher
  "A generic implementation for stream
  ciphers initialization process."
  [engine {:keys [iv key op] :or {op :encrypt}}]
  (assert (instance? StreamCipher engine) "Should be stream cipher.")
  (let [params (if (nil? iv)
                 (KeyParameter. key)
                 (ParametersWithIV. (KeyParameter. key) iv))
        encrypt? (case op
                   :encrypt true
                   :decrypt false)]
    (.init ^StreamCipher engine encrypt? params)
    engine))

(defn- init-aead-cipher
  "A generic implementation for block cipher
  initialization process."
  [engine {:keys [iv key op aad tagsize] :or {op :encrypt tagsize 128}}]
  (assert (instance? AEADBlockCipher engine) "Should be aead block cipher.")
  (let [params (-> (KeyParameter. key)
                   (AEADParameters. tagsize iv aad))
        encrypt? (case op
                   :encrypt true
                   :decrypt false)]
      (.init ^AEADBlockCipher engine encrypt? params)
      engine))

(defn- end-aead-cipher
  [engine out offset]
  (.doFinal ^AEADBlockCipher engine ^bytes out (int offset)))

;; --- Public Api

(defn output-size
  "Get the output size of the aead block cipher."
  [^AEADBlockCipher engine length]
  (.getOutputSize engine (int length)))

(def get-output-size
  "A backward compatibility alias for `output-size` function."
  output-size)

(defn block-size
  "Return the block size of the block cipher."
  [^BlockCipher engine]
  (.getBlockSize engine))

(def get-block-size
  "A backward compatibility alias for `output-size` function."
  block-size)

(defprotocol ICipherInit
  (-init [engine params] "Initialize cipher engine.")
  (-end [engine out offset] "Finalize cipher engine."))

(extend BlockCipher
  ICipherInit
  {:-init init-block-cipher
   :-end (constantly 0)})

(extend StreamCipher
  ICipherInit
  {:-init init-stream-cipher
   :-end (constantly 0)})

(extend AEADBlockCipher
  ICipherInit
  {:-init init-aead-cipher
   :-end end-aead-cipher})

(defn init!
  "Initialize the cipher engine."
  [engine params]
  (-init engine params))

(def initialize!
  "A backward compatibility alias for `init!`"
  init!)

(defprotocol IBlockCipherLike
  (^:private -process-block [_ in inoff out outoff]))

(defprotocol IStreamCipherLike
  (^:private -process-bytes [_ in inoff inlen out outoff]))

(extend-protocol IBlockCipherLike
  BlockCipher
  (-process-block [e in inoff out outoff]
    (.processBlock ^BlockCipher e in inoff out outoff))

  AEADBlockCipher
  (-process-block [e ^bytes in inoff out outoff]
    (.processBytes ^AEADBlockCipher e in (int inoff) (alength in) out (int outoff)))

  StreamCipher
  (-process-block [e ^bytes in inoff out outoff]
    (.processBytes ^StreamCipher e in (int inoff) (alength in) out (int outoff))))

(extend-protocol IStreamCipherLike
  AEADBlockCipher
  (-process-bytes [e in inoff inlen out outoff]
    (.processBytes ^AEADBlockCipher e in (int inoff) (int inlen) out (int outoff)))

  StreamCipher
  (-process-bytes [e in inoff inlen out outoff]
    (.processBytes ^StreamCipher e in (int inoff) (int inlen) out (int outoff))))

(defn process-block!
  "Encrypt or decrypt a bytes using the specified engine.
  The length of the block to encrypt or decrypt depends on the used
  crypto engine."
  ([engine in]
   (let [out (byte-array (block-size engine))]
     (-process-block engine in 0 out 0)
     out))
  ([engine in inoff out outoff]
   (-process-block engine in inoff out outoff)))

(defn process-bytes!
  "Encrypt or decrypt a bytes using the specified engine.
  Is a specialized version of `process-block!` for stream ciphers
  and aead ciphers."
  ([engine ^bytes in]
   (let [length (alength in)
         out    (byte-array length)]
     (-process-bytes engine in 0 length out 0)
     out))
  ([engine ^bytes in inoff out outoff]
   (-process-bytes engine in inoff (alength in) out outoff))
  ([engine in inoff inlen out outoff]
   (-process-bytes engine in inoff inlen out outoff)))

(defn end!
  "End the encryption process.
  This is only usefull for aead block ciphers, for the
  rest it always return `0` and does nothing."
  [engine output offset]
  (-end engine output offset))

(defn block-cipher
  "Block cipher engine constructor."
  [alg mode]
  (if-let [modefactory (get +cipher-modes+ mode)]
    (if-let [enginefactory (get +block-cipher-engines+ alg)]
      (modefactory (enginefactory))
      (throw (ex-info "Cipher algorighm not supported." {:alg alg})))
    (throw (ex-info "Cipher mode not supported." {:mode mode}))))

(defn stream-cipher
  "Stream cipher engine constructor."
  [alg]
  (if-let [enginefactory (get +stream-cipher-engines+ alg)]
    (enginefactory)
    (throw (ex-info "Cipher algorighm not supported." {:alg alg}))))

(defn split-by-blocksize
  "Split a byte array in blocksize blocks.

  Given a arbitrary size bytearray and block size in bytes, returns a
  vector of bytearray blocks of blocksize size. If last block does not
  have enought data for fill all block, it is padded using zerobyte
  padding."
  ([^bytes input ^long blocksize]
   (split-by-blocksize input blocksize false))
  ([^bytes input ^long blocksize additional]
   (let [inputsize (count input)]
     (loop [cursormin 0
            cursormax blocksize
            remain inputsize
            result (transient [])]
       (cond
         (= remain 0)
         (persistent!
          (if additional
            (conj! result (byte-array blocksize))
            result))

         (< remain blocksize)
         (let [buffer (byte-array blocksize)]
           (System/arraycopy input cursormin buffer 0 remain)
           (persistent!
            (conj! result buffer)))

         (>= remain blocksize)
         (let [buffer (byte-array blocksize)]
           (System/arraycopy input cursormin buffer 0 blocksize)
           (recur cursormax
                  (+ cursormax blocksize)
                  (- inputsize cursormax)
                  (conj! result buffer))))))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; High-Level Api
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;; Links to rfcs:
;; - http://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05

(def ^:private keylength? #(= (count %1) %2))
(def ^:private ivlength? #(= (count %1) %2))

(defn encrypt-cbc
  "Encrypt arbitrary length input using the provided engine, key and iv
  using cbc encryption mode and the pkcs7 padding acording to the
  aead-aes-cbc-hmac encryption scheme."
  {:internal true :no-doc true}
  [cipher input key iv]
  (let [blocksize (get-block-size cipher)
        blocks (split-by-blocksize input blocksize true)
        inputsize (count input)]
    (initialize! cipher {:op :encrypt :iv iv :key key})
    (apply bytes/concat
           (loop [blocks blocks
                  processed (transient [])
                  pos 0]
             (let [block (first blocks)
                   last? (empty? (rest blocks))]
               (if-not last?
                 (recur (rest blocks)
                        (conj! processed (process-block! cipher block))
                        (+ pos (count block)))
                 (let [remaining (- inputsize pos)]
                   (padding/pad! block remaining :pkcs7)
                   (persistent!
                    (conj! processed (process-block! cipher block))))))))))

(defn decrypt-cbc
  "Dencrypt arbitrary length input using the provided engine, key and iv
  using cbc encryption mode and the pkcs7 padding acording to the
  aead-aes-cbc-hmac encryption scheme."
  {:internal true :no-doc true}
  [cipher input key iv]
  (let [blocksize (get-block-size cipher)
        blocks (split-by-blocksize input blocksize false)]
    (initialize! cipher {:op :decrypt :iv iv :key key})
    (apply bytes/concat
           (loop [blocks blocks
                  processed (transient [])]
             (let [block (process-block! cipher (first blocks))
                   last? (empty? (rest blocks))]
               (if-not last?
                 (recur (rest blocks)
                        (conj! processed block))
                 (let [result (padding/unpad block :pkcs7)]
                   (persistent!
                    (conj! processed result)))))))))

(defn encrypt-gcm
  "Encrypt arbitrary length input using the provided engine, key and iv
  using cbc encryption mode and the pkcs7 padding acording to the
  aead-aes-gcm encryption scheme."
  {:internal true :no-doc true}
  [cipher input key iv aad]
  (-init cipher {:iv iv :key key :tagsize 128 :op :encrypt :aad aad})
  (let [outputlength (get-output-size cipher (count input))
        output (byte-array outputlength)
        offset (process-bytes! cipher input 0 output 0)]
    (try
      (-end cipher output offset)
      (catch InvalidCipherTextException e
        (as-> (str "Couldn't generate gcm authentication tag: " (.getMessage e)) $
          (throw (ex-info $ {:type :encryption :cause :authtag})))))
    output))

(defn decrypt-gcm
  "Dencrypt arbitrary length input using the provided engine, key and iv
  using cbc encryption mode and the pkcs7 padding acording to the
  aead-aes-gcm encryption scheme."
  {:internal true :no-doc true}
  [cipher ciphertext key iv aad]
  (-init cipher {:iv iv :key key :tagsize 128 :op :decrypt :aad aad})
  (let [input (bytes/copy ciphertext)
        outputlength (get-output-size cipher (count input))
        output (byte-array outputlength)
        offset (process-bytes! cipher input 0 output 0)]
    (try
      (-end cipher output offset)
      (catch InvalidCipherTextException e
        (as-> (str "Couldn't validate gcm authentication tag: " (.getMessage e)) $
          (throw (ex-info $ {:type :validation :cause :authtag})))))
    output))

(defn- aad->bytes
  [aad]
  (let [length (* (count aad) 8)
        buffer (ByteBuffer/allocate 8)]
    (.putLong buffer length)
    (.array buffer)))

(defn- extract-encryption-key
  [key alg]
  {:pre [(bytes/bytes? key)]}
  (case alg
    :aes128-cbc-hmac-sha256 (bytes/slice key 16 32)
    :aes192-cbc-hmac-sha384 (bytes/slice key 24 48)
    :aes256-cbc-hmac-sha512 (bytes/slice key 32 64)))

(defn- extract-authentication-key
  [key alg]
  {:pre [(bytes/bytes? key)]}
  (case alg
    :aes128-cbc-hmac-sha256 (bytes/slice key 0 16)
    :aes192-cbc-hmac-sha384 (bytes/slice key 0 24)
    :aes256-cbc-hmac-sha512 (bytes/slice key 0 32)))

(defn- generate-authtag
  [{:keys [alg input authkey iv aad] :as params}]
  (let [al (if aad
             (aad->bytes aad)
             (byte-array 0))
        data (bytes/concat aad iv input al)
        fulltag (mac/hash data {:key authkey :alg :hmac :digest alg})
        truncatesize (quot (count fulltag) 2)]
    (bytes/slice fulltag 0 truncatesize)))

(defn- verify-authtag
  [tag params]
  (let [tag' (generate-authtag params)]
    (bytes/equals? tag tag')))

(defmulti -encrypt :alg)
(defmulti -decrypt :alg)

(defmethod -encrypt :aes128-cbc-hmac-sha256
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key alg)
        authkey (extract-authentication-key key alg)
        ciphertext (encrypt-cbc cipher input encryptionkey iv)
        tag (generate-authtag {:alg :sha256
                               :input ciphertext
                               :authkey authkey
                               :aad aad
                               :iv iv})]
    (bytes/concat ciphertext tag)))

(defmethod -decrypt :aes128-cbc-hmac-sha256
  [{:keys [alg input key iv] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key alg)
        authkey (extract-authentication-key key alg)
        [ciphertext authtag] (let [inputlen (count input)
                                   taglen (quot 32 2) ciphertext (bytes/slice input 0 (- inputlen taglen))
                                   tag (bytes/slice input (- inputlen taglen) inputlen)]
                               [ciphertext tag])]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :alg :sha256 :input ciphertext))
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :authtag})))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod -encrypt :aes192-cbc-hmac-sha384
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 48) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key alg)
        authkey (extract-authentication-key key alg)
        ciphertext (encrypt-cbc cipher input encryptionkey iv)
        tag (generate-authtag {:alg :sha384
                               :input ciphertext
                               :authkey authkey
                               :iv iv
                               :aad aad})]
    (bytes/concat ciphertext tag)))

(defmethod -decrypt :aes192-cbc-hmac-sha384
  [{:keys [alg input key iv] :as params}]
  {:pre [(keylength? key 48) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key alg)
        authkey (extract-authentication-key key alg)
        [ciphertext authtag] (let [inputlen (count input)
                                   taglen (quot 48 2) ciphertext (bytes/slice input 0 (- inputlen taglen))
                                   tag (bytes/slice input (- inputlen taglen) inputlen)]
                               [ciphertext tag])]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :alg :sha384 :input ciphertext))
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :authtag})))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod -encrypt :aes256-cbc-hmac-sha512
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 64) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key alg)
        authkey (extract-authentication-key key alg)
        ciphertext (encrypt-cbc cipher input encryptionkey iv)
        tag (generate-authtag {:alg :sha512
                               :input ciphertext
                               :authkey authkey
                               :iv iv
                               :aad aad})]
    (bytes/concat ciphertext tag)))

(defmethod -decrypt :aes256-cbc-hmac-sha512
  [{:keys [alg input key iv] :as params}]
  {:pre [(keylength? key 64) (ivlength? iv 16)]}
  (let [cipher (block-cipher :aes :cbc)
        encryptionkey (extract-encryption-key key alg)
        authkey (extract-authentication-key key alg)
        [ciphertext authtag] (let [inputlen (count input)
                                   taglen (quot 64 2) ciphertext (bytes/slice input 0 (- inputlen taglen))
                                   tag (bytes/slice input (- inputlen taglen) inputlen)]
                               [ciphertext tag])]
    (when-not (verify-authtag authtag (assoc params :authkey authkey :alg :sha512 :input ciphertext))
      (throw (ex-info "Message seems corrupt or manipulated."
                      {:type :validation :cause :authtag})))
    (decrypt-cbc cipher ciphertext encryptionkey iv)))

(defmethod -encrypt :aes128-gcm
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 16) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (encrypt-gcm cipher input key iv aad)))

(defmethod -decrypt :aes128-gcm
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 16) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (decrypt-gcm cipher input key iv aad)))

(defmethod -encrypt :aes192-gcm
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 24) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (encrypt-gcm cipher input key iv aad)))

(defmethod -decrypt :aes192-gcm
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 24) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (decrypt-gcm cipher input key iv aad)))

(defmethod -encrypt :aes256-gcm
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (encrypt-gcm cipher input key iv aad)))

(defmethod -decrypt :aes256-gcm
  [{:keys [alg input key iv aad] :as params}]
  {:pre [(keylength? key 32) (ivlength? iv 12)]}
  (let [cipher (block-cipher :aes :gcm)]
    (decrypt-gcm cipher input key iv aad)))

(defn encrypt
  "Encrypt arbitrary length data using one of the supported encryption
  scheme. The default encryption scheme is: `:aes128-cbc-hmac-sha256`.

  Example: `(encrypt \"hello world\" mykey myiv)`

  You can specify an other encryption scheme passing an additional
  parameter.

  Example: `(encrypt \"hello world\" mykey myiv {:alg :aes128-cbc-hmac-sha512})`

  See the documentation for know the complete list of supported
  encryption schemes.

  The input, key and iv parameters should be of any type
  that can be coerced to byte array."
  ([input key iv]
   (encrypt input key iv nil))
  ([input key iv {:keys [algorithm alg]
                  :or {alg :aes128-cbc-hmac-sha256}
                  :as options}]
   (let [key (codecs/to-bytes key)
         iv  (codecs/to-bytes iv)
         alg (or algorithm alg)]
     (-encrypt (assoc options
                      :alg alg
                      :input input
                      :key key
                      :iv iv)))))

(defn decrypt
  "Decrypt data encrypted using the `encrypt` function.

  The input, key and iv parameters should be of any type that can be
  coerced to byte array."
  ([input key iv]
   (decrypt input key iv {}))
  ([input key iv {:keys [algorithm alg]
                  :or {alg :aes128-cbc-hmac-sha256}
                  :as options}]
   (let [key (codecs/to-bytes key)
         iv  (codecs/to-bytes iv)
         alg (or algorithm alg)]
     (-decrypt (assoc options
                      :alg alg
                      :input input
                      :key key
                      :iv iv)))))
