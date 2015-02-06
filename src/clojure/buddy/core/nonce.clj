(ns buddy.core.nonce
  "Namespace dedicated to provide an abstraction
  for generate a valid secure nonce values.

  By convenience, it also exposes additional functions
  for generate random iv/salts.")

(defn random-bytes
  "Generate a byte array of scpecified length with random
  bytes taken from secure random number generator.
  This method should be used for generate a random
  iv/salt or arbitrary length."
  ([^long numbytes]
   (make-random-bytes numbytes (SecureRandom.)))
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
     (.putBytes buffer (random-bytes (.remaining buffer) sr))
     (.array buffer))))

