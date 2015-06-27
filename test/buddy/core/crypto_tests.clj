;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.crypto-tests
  (:require [clojure.test :refer :all]
            [clojure.pprint :refer :all]
            [buddy.core.codecs :as codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :refer :all]
            [buddy.core.nonce :as nonce]
            [buddy.core.hash :as hash]
            [buddy.core.crypto :as crypto]
            [clojure.java.io :as io]))

(deftest low-level-api-tests
  (let [key     (nonce/random-bytes 32)
        iv      (nonce/random-bytes 16)
        key     (hex->bytes "0000000000000000000000000000000000000000000000000000000000000000")
        iv16    (hex->bytes "00000000000000000000000000000000")
        iv8     (hex->bytes "0011001100110011")
        block16 (hex->bytes "000000000000000000000000000000AA")
        block3  (hex->bytes "121314")
        block6  (hex->bytes "221122112211")]

    (testing "Twofish in CRT mode."
      (let [engine    (crypto/block-cipher :twofish :ctr)
            expected1 (into-array Byte/TYPE [87 -1 115 -99 77 -55 44 27 -41 -4 1 112 12 -56 33 -59])
            expected2 (into-array Byte/TYPE [35 -47 36 126 -1 76 -88 -53 -77 120 -33 17 -125 105 -126 -76])]

        ;; Encrypt
        (crypto/initialize! engine {:iv iv16 :key key :op :encrypt})
        (let [result1 (crypto/process-block! engine block16)
              result2 (crypto/process-block! engine block16)]
          (is (bytes/bytes? result1))
          (is (bytes/bytes? result2))
          (is (bytes/equals? expected1 result1))
          (is (bytes/equals? expected2 result2)))

        ;; Decrypt
        (crypto/initialize! engine {:iv iv16 :key key :op :decrypt})
        (let [result1 (crypto/process-block! engine expected1)
              result2 (crypto/process-block! engine expected2)]
          (is (bytes/equals? result1 block16))
          (is (bytes/equals? result2 block16)))))

    (testing "Aes in :cbc mode"
      (let [engine   (crypto/block-cipher :aes :cbc)
            expected (into-array Byte/TYPE [-121 104 86 98 109 -110 53 104 119 -94
                                            -124 -105 92 39 -30 -30])]
        ;; Encrypt
        (crypto/initialize! engine {:iv iv16 :key key :op :encrypt})
        (let [result (crypto/process-block! engine block16)]
          (is (bytes/equals? result expected)))

        ;; Decrypt
        (crypto/initialize! engine {:iv iv16 :key key :op :decrypt})
        (let [result (crypto/process-block! engine expected)]
          (is (bytes/equals? result block16)))))

    (testing "ChaCha Streaming Cipher"
      (let [engine    (crypto/stream-cipher :chacha)
            expected1 (into-array Byte/TYPE [14, 37, 45])
            expected2 (into-array Byte/TYPE [-5, 46, -80, -91, 19, -12])]
        (crypto/initialize! engine {:iv iv8 :key key :op :encrypt})
        (let [result1 (crypto/process-block! engine block3)
              result2 (crypto/process-block! engine block6)]
          (is (bytes/equals? result1 expected1))
          (is (bytes/equals? result2 expected2)))

        (crypto/initialize! engine {:iv iv8 :key key :op :decrypt})
        (let [result1 (crypto/process-block! engine expected1)
              result2 (crypto/process-block! engine expected2)]
          (is (bytes/equals? result1 block3))
          (is (bytes/equals? result2 block6)))))
))

(deftest low-level-aead-mode-tests
  (let [key (hex->bytes "0000000000000000000000000000000000000000000000000000000000000000")
        data (nonce/random-bytes 256)
        iv16 (nonce/random-bytes 16)
        cipher (crypto/block-cipher :aes :gcm)]
    (crypto/initialize! cipher {:iv iv16 :key key :op :encrypt})
    (let [finalsize (crypto/get-output-size cipher (count data))]
      (is (= finalsize 272)))
    (let [output (byte-array 272)
          offset (crypto/process-block! cipher data 0 output 0)
          offset' (crypto/calculate-authtag! cipher output offset)]
      (crypto/initialize! cipher {:iv iv16 :key key :op :decrypt})
      (let [input output
            finalsize (crypto/get-output-size cipher (count input))]
        (is (= finalsize 256))
        (let [output (byte-array 256)
              offset (crypto/process-block! cipher input 0 output 0)
              offset' (crypto/calculate-authtag! cipher output offset)]
          (is (bytes/equals? output data)))))))

(deftest high-level-api-tests
  (let [key64 (nonce/random-bytes 64)
        key48 (nonce/random-bytes 48)
        key32 (nonce/random-bytes 32)
        key24 (nonce/random-bytes 24)
        key16 (nonce/random-bytes 16)
        iv12 (nonce/random-bytes 12)
        iv16 (nonce/random-bytes 16)]
    ;; (testing "Experiment"
    ;;   (let [data (into-array Byte/TYPE [35 -117 48 0])
    ;;         encrypted (crypto/encrypt data key32 iv16)
    ;;         decrypted (crypto/decrypt encrypted key32 iv16)]
    ;;     (println 222 (vec data))
    ;;     (println 333 (vec decrypted))
    ;;     (is (bytes/equals? decrypted data))))

    (testing "Encrypt and decript using :aes128-cbc-hmac-sha256."
      (dotimes [i 50]
        (doseq [i (range 1 100)]
          (let [data  (nonce/random-bytes i)
                encrypted (crypto/encrypt data key32 iv16)
                decrypted (crypto/decrypt encrypted key32 iv16)]
            (is (bytes/equals? decrypted data))))))

    (testing "Encrypt and decript using :aes192-cbc-hmac-sha384."
      (dotimes [i 50]
        (doseq [i (range 1 100)]
          (let [data  (nonce/random-bytes i)
                encrypted (crypto/encrypt data key48 iv16 {:algorithm :aes192-cbc-hmac-sha384})
                decrypted (crypto/decrypt encrypted key48 iv16 {:algorithm :aes192-cbc-hmac-sha384})]
            (is (bytes/equals? decrypted data))))))

    (testing "Encrypt and decript using :aes256-cbc-hmac-sha512."
      (dotimes [i 50]
        (doseq [i (range 1 100)]
          (let [data  (nonce/random-bytes i)
                encrypted (crypto/encrypt data key64 iv16 {:algorithm :aes256-cbc-hmac-sha512})
                decrypted (crypto/decrypt encrypted key64 iv16 {:algorithm :aes256-cbc-hmac-sha512})]
            (is (bytes/equals? decrypted data))))))

    (testing "Encrypt and decript using :aes128-gcm."
      (dotimes [i 50]
        (doseq [i (range 1 100)]
          (let [data  (nonce/random-bytes i)
                encrypted (crypto/encrypt data key16 iv12 {:algorithm :aes128-gcm})
                decrypted (crypto/decrypt encrypted key16 iv12 {:algorithm :aes128-gcm})]
            (is (bytes/equals? decrypted data))))))

    (testing "Encrypt and decript using :aes192-gcm."
      (dotimes [i 50]
        (doseq [i (range 1 100)]
          (let [data  (nonce/random-bytes i)
                encrypted (crypto/encrypt data key24 iv12 {:algorithm :aes192-gcm})
                decrypted (crypto/decrypt encrypted key24 iv12 {:algorithm :aes192-gcm})]
            (is (bytes/equals? decrypted data))))))

    (testing "Encrypt and decript using :aes256-gcm."
      (dotimes [i 50]
        (doseq [i (range 1 100)]
          (let [data  (nonce/random-bytes i)
                encrypted (crypto/encrypt data key32 iv12 {:algorithm :aes256-gcm})
                decrypted (crypto/decrypt encrypted key32 iv12 {:algorithm :aes256-gcm})]
            (is (bytes/equals? decrypted data))))))
))
