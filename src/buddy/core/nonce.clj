;; Copyright 2013-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.nonce
  "Namespace dedicated to provide an abstraction
  for generate a valid secure nonce values.

  By convenience, it also exposes additional functions
  for generate random iv/salts."
  (:import java.security.SecureRandom
           org.bouncycastle.crypto.BlockCipher
           org.bouncycastle.crypto.modes.SICBlockCipher
           org.bouncycastle.crypto.engines.ChaChaEngine))


(defn random-bytes
  "Generate a byte array of specified length with random
  bytes taken from secure random number generator.
  This method should be used to generate a random
  iv/salt or arbitrary length."
  ([^long numbytes]
   (random-bytes numbytes (SecureRandom.)))
  ([^long numbytes ^SecureRandom sr]
   (let [buffer (byte-array numbytes)]
     (.nextBytes sr buffer)
     buffer)))

(defn random-nonce
  "Generate a secure nonce based on current time
  and additional random data obtained from secure random
  generator. The minimum value is 8 bytes, and recommended
  minimum value is 32."
  ([^long numbytes]
   (random-nonce numbytes (SecureRandom.)))
  ([^long numbytes ^SecureRandom sr]
   (let [buffer (java.nio.ByteBuffer/allocate numbytes)]
     (.putLong buffer (System/currentTimeMillis))
     (.put buffer ^bytes (random-bytes (.remaining buffer) sr))
     (.array buffer))))


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Helpers for generate specific iv/nonces for engines
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defmulti for-engine class)

(defmethod for-engine ChaChaEngine [e] (random-nonce 8))
(defmethod for-engine SICBlockCipher [^BlockCipher e] (random-nonce (.getBlockSize e)))
(defmethod for-engine BlockCipher [^BlockCipher e] (random-bytes (.getBlockSize e)))
