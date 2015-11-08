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

(ns buddy.core.kdf-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as c]
            [buddy.core.bytes :as b]
            [buddy.core.keys :as k]
            [buddy.core.nonce :as n]
            [buddy.core.kdf :as kdf]
            [clojure.java.io :as io]))

(deftest hkdf-sha256-test
  (let [key (c/hex->bytes "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        salt (c/hex->bytes "000102030405060708090a0b0c")
        info (c/hex->bytes "f0f1f2f3f4f5f6f7f8f9")
        expected (c/hex->bytes (str "3cb25f25faacd57a90434f64d0362f2a"
                                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                                    "34007208d5b887185865"))
        engine (kdf/engine {:key key :salt salt :info info :alg :hkdf+sha256})
        result (kdf/get-bytes engine 42)]
    ;; (println (c/bytes->hex result))
    ;; (println (c/bytes->hex expected))
    (is (b/equals? result expected))))

(deftest kdf1-sha1-test
  (let [key (c/hex->bytes "deadbeeffeebdaed")
        engine (kdf/engine {:key key :alg :kdf1 :digest :sha1})
        expected (c/hex->bytes (str "B0AD565B14B478CAD4763856FF3016B1A93D840"
                                    "F87261BEDE7DDF0F9305A6E44"))
        result (kdf/get-bytes engine 32)]
    ;; (println (c/bytes->hex result))
    ;; (println (c/bytes->hex expected))
    (is (b/equals? result expected))))

(deftest kdf2-sha1-test
  (let [key (c/hex->bytes "deadbeeffeebdaed")
        engine (kdf/engine {:key key :alg :kdf2 :digest :sha1})
        expected (c/hex->bytes (str "87261BEDE7DDF0F9305A6E44A74E6A0846DEDE27"
                                    "F48205C6B141888742B0CE2C"))
        result (kdf/get-bytes engine 32)]
    ;; (println (c/bytes->hex result))
    ;; (println (c/bytes->hex expected))
    (is (b/equals? result expected))))
