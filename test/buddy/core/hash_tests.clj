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

(ns buddy.core.hash-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs :refer :all]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :refer :all]
            [buddy.core.hash :as hash]
            [clojure.java.io :as io]))

(deftest buddy-core-hash
  (testing "SHA3 support test"
    (let [plain-text "FooBar"
          hashed     (-> (hash/sha3-256 plain-text)
                         (bytes->hex))]
      (is (= hashed "0a3c119a02a37e50fbaf8a3776559c76de7a969097c05bd0f41f60cf25210745"))))
  (testing "File hashing"
    (let [path       "test/_files/pubkey.ecdsa.pem"
          valid-hash "7aa01e35e65701c9a9d8f71c4cbf056acddc9be17fdff06b4c7af1b0b34ddc29"]
      (is (= (bytes->hex (hash/sha256 (io/input-stream path))) valid-hash)))))
