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

(ns buddy.core.mac-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :refer :all]
            [buddy.core.nonce :as nonce]

            [buddy.core.mac :as mac]
            [clojure.java.io :as io])
  (:import org.bouncycastle.crypto.digests.SHA256Digest
           org.bouncycastle.crypto.macs.HMac))


(deftest hmac-tests
  (let [secretkey "my.secret.key"
        path      "test/_files/pubkey.ecdsa.pem"]

    (testing "Multiple sign using hmac sha256"
      (is (bytes/equals? (mac/hash "foo" {:key secretkey :alg :hmac+sha256})
                         (mac/hash "foo" {:key secretkey :alg :hmac+sha256}))))

    (testing "Test Vector"
      (let [key (hex->bytes (str "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
            data (str->bytes "Test Using Larger Than Block-Size Key - Hash Key First")
            result "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"]
        (is (= result (bytes->hex (mac/hash data {:key key :alg :hmac+sha256}))))
        (is (= result (bytes->hex (mac/hash data {:key key :alg :hmac :digest :sha256}))))
        (is (= result (bytes->hex (mac/hash data {:key key :alg :hmac :digest (SHA256Digest.)}))))))

    (testing "Test simple hmac sha1"
      (let [secretkey "b"
            data "a"
            sig (bytes->hex (mac/hash data {:key secretkey :alg :hmac+sha1}))
            result "8abe0fd691e3da3035f7b7ac91be45d99e942b9e"]
        (is (= result sig))))

    (testing "Test simple hmac sha256"
      (let [secretkey "b"
            data "a"
            sig (bytes->hex (mac/hash data {:key secretkey :alg :hmac+sha256}))
            result "cb448b440c42ac8ad084fc8a8795c98f5b7802359c305eabd57ecdb20e248896"]
        (is (= result sig))))

    (testing "Test simple hmac sha384"
      (let [secretkey "b"
            data "a"
            sig (bytes->hex (mac/hash data {:key secretkey :alg :hmac+sha384}))
            result "40292a79a280f609aef472272d2a2a0d148bfb83fa18fd2806440d07d16e31d9f0d398891063c11f6c73891e6f646106"]
        (is (= result sig))))

    (testing "Test simple hmac sha512"
      (let [secretkey "b"
            data "a"
            sig (bytes->hex (mac/hash data {:key secretkey :alg :hmac+sha512}))
            result "68c1687fa7cb5170ff800580a0cec29dc0ccb515aaf95587bdfe5c923730a7852e2beefefd6be31d97aa612ad8b8569bba61ed2c339cd9b28409751b0b9e96a0"]
        (is (= result sig))))

    (testing "Sign/Verify string"
      (let [sig (mac/hash "foo" {:key secretkey :alg :hmac+sha384})]
        (is (true? (mac/verify "foo" sig {:key secretkey :alg :hmac+sha384})))))

    (testing "Sign/Verify input stream"
      (let [sig (mac/hash (io/input-stream path) {:key secretkey :alg :hmac+sha512})]
        (is (true? (mac/verify (io/input-stream path) sig {:key secretkey :alg :hmac+sha512})))))

    (testing "Sign/Verify file"
      (let [sig (mac/hash (java.io.File. path) {:key secretkey :alg :hmac+sha512})]
        (is (true? (mac/verify (java.io.File. path) sig {:key secretkey :alg :hmac+sha512})))))

    (testing "Sign/Verify url"
      (let [sig (mac/hash (.toURL (java.io.File. path)) {:key secretkey :alg :hmac+sha512})]
        (is (true? (mac/verify (.toURL (java.io.File. path)) sig {:key secretkey :alg :hmac+sha512})))))

    (testing "Sign/Verify uri"
      (let [sig (mac/hash (.toURI (java.io.File. path)) {:key secretkey :alg :hmac+sha512})]
        (is (true? (mac/verify (.toURI (java.io.File. path)) sig {:key secretkey :alg :hmac+sha512})))))
    ))

(deftest poly1305-tests
  (let [plaintext "text"
        iv (nonce/random-bytes 16)    ;; IV required by poly1305
        iv' (nonce/random-bytes 16)
        key (nonce/random-bytes 32)]  ;; KEY required by poly1305

    (testing "Poly1305 with same iv"
      (let [result1 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})
            result2 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})]
        (is (bytes/equals? result1 result2))))

    (testing "Poly1305 with different iv"
      (let [result1 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})
            result2 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv'})]
        (is (not (bytes/equals? result1 result2)))))

    (testing "Poly1305 verify"
      (let [rs (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})]
        (is (mac/verify plaintext rs {:key key :alg :poly1305+aes :iv iv}))
        (is (not (mac/verify plaintext rs {:key key :alg :poly1305+aes :iv iv'})))))

    (testing "Poly1305 constructor"
      (let [result1 (mac/hash plaintext {:key key :alg :poly1305 :cipher :aes :iv iv})
            result2 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})
            result3 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv'})]
        (is (bytes/equals? result1 result2))
        (is (not (bytes/equals? result1 result3)))))

    (testing "Poly1305 + Twofish"
      (let [result1 (mac/hash plaintext {:key key :alg :poly1305 :cipher :twofish :iv iv})
            result2 (mac/hash plaintext {:key key :alg :poly1305+twofish :iv iv})
            result3 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})]
        (is (bytes/equals? result1 result2))
        (is (not (bytes/equals? result1 result3)))))

    (testing "Poly1305 + Serpent"
      (let [result1 (mac/hash plaintext {:key key :alg :poly1305 :cipher :serpent :iv iv})
            result2 (mac/hash plaintext {:key key :alg :poly1305+serpent :iv iv})
            result3 (mac/hash plaintext {:key key :alg :poly1305+twofish :iv iv})
            result4 (mac/hash plaintext {:key key :alg :poly1305+aes :iv iv})]
        (is (bytes/equals? result1 result2))
        (is (not (bytes/equals? result1 result3)))
        (is (not (bytes/equals? result1 result4)))))

  (testing "Poly1305 + Serpent + File"
    (let [path "test/_files/pubkey.ecdsa.pem"
          sig  (mac/hash (io/input-stream path) {:key key :alg :poly1305+serpent :iv iv})]
      (is (mac/verify (io/input-stream path) sig {:key key :alg :poly1305+serpent :iv iv}))))
  ))
