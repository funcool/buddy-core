;; Copyright 2014-2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.test-buddy-core-mac
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :refer :all]
            [buddy.core.nonce :as nonce]
            [buddy.core.mac.poly1305 :as poly]
            [buddy.core.mac.hmac :as hmac]
            [buddy.core.mac.shmac :as shmac]
            [clojure.java.io :as io]))

(deftest buddy-core-mac-hmac
  (let [secretkey "my.secret.key"
        path      "test/_files/pubkey.ecdsa.pem"]

    (testing "Multiple sign using hmac sha256"
      (is (bytes/equals? (hmac/hash "foo" secretkey :sha256)
                         (hmac/hash "foo" secretkey :sha256))))

    (testing "Test Vector"
      (let [key (hex->bytes (str "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aaaaaaaaaaaaaaaaaaaaaaaaaa"
                                 "aa"))
            data (str->bytes "Test Using Larger Than Block-Size Key - Hash Key First")
            result "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"]
        (is (= result (bytes->hex (hmac/hash data key :sha256))))))

    (testing "Sign/Verify string"
      (let [sig (hmac/hash "foo" secretkey :sha384)]
        (is (true? (hmac/verify "foo" sig secretkey :sha384)))))

    (testing "Sign/Verify input stream"
      (let [sig (hmac/hash (io/input-stream path) secretkey :sha512)]
        (is (true? (hmac/verify (io/input-stream path) sig secretkey :sha512)))))

    (testing "Sign/Verify file"
      (let [sig (hmac/hash (java.io.File. path) secretkey :sha512)]
        (is (true? (hmac/verify (java.io.File. path) sig secretkey :sha512)))))

    (testing "Sign/Verify url"
      (let [sig (hmac/hash (.toURL (java.io.File. path)) secretkey :sha512)]
        (is (true? (hmac/verify (.toURL (java.io.File. path)) sig secretkey :sha512)))))

    (testing "Sign/Verify uri"
      (let [sig (hmac/hash (.toURI (java.io.File. path)) secretkey :sha512)]
        (is (true? (hmac/verify (.toURI (java.io.File. path)) sig secretkey :sha512)))))

    (testing "Sign/Verify salted hmac with string"
      (let [sig (shmac/shmac "foo" secretkey "salt" :sha256)]
        (is (true? (shmac/verify "foo" sig secretkey "salt" :sha256)))))))

(deftest buddy-core-mac-poly1305
  (let [plaintext "text"
        secretkey "secret"]
    (testing "Poly1305 encrypt/verify (using string key)"
      (let [mac-bytes1 (poly/poly1305 plaintext secretkey :aes)
            mac-bytes2 (poly/poly1305 plaintext secretkey :aes)]
        (is (not (bytes/equals? mac-bytes1 mac-bytes2))))

      (let [mac-bytes1 (poly/hash plaintext secretkey :aes)
            mac-bytes2 (poly/hash plaintext secretkey :aes)]
        (is (not (bytes/equals? mac-bytes1 mac-bytes2)))))

  (testing "File mac"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          macbytes   (poly/poly1305 (io/input-stream path) secretkey :aes)]
      (is (poly/verify (io/input-stream path) macbytes secretkey :aes))))

  (testing "Poly1305-Twofish env/verify"
    (let [signature (poly/poly1305 plaintext secretkey :twofish)]
      (is (poly/verify plaintext signature secretkey :twofish))))

  (testing "Poly1305-Serpent env/verify"
    (let [signature (poly/poly1305 plaintext secretkey :serpent)]
      (is (poly/verify plaintext signature secretkey :serpent))))
))
