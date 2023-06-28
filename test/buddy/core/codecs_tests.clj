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

(ns buddy.core.codecs-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs :refer :all]
            [buddy.core.codecs.base64 :as b64]
            [buddy.core.bytes :as bytes]
            [buddy.core.keys :refer :all]
            [buddy.core.hash :as hash]
            [clojure.java.io :as io]))

(deftest buddy-core-codecs
  (testing "Hex encode/decode 01"
    (let [some-bytes  (str->bytes "FooBar")
          encoded     (bytes->hex some-bytes)
          decoded     (hex->bytes encoded)
          some-str    (bytes->str decoded)]
      (is (bytes/equals? decoded, some-bytes))
      (is (= some-str "FooBar"))))

  (testing "Hex encode/decode 02"
    (let [mybytes (into-array Byte/TYPE (range 10))
          encoded (bytes->hex mybytes)
          decoded (hex->bytes encoded)]
      (is (bytes/equals? decoded mybytes))))

  (testing "Safe base64 encode/decode"
    (let [output1 (b64/encode "foo" true)
          output2 (b64/decode output1)]
      (is (= (bytes->str output1) "Zm9v"))
      (is (= (bytes->str output2) "foo"))))

  (testing "Concat byte arrays"
    (let [array1 (into-array Byte/TYPE [1,2,3])
          array2 (into-array Byte/TYPE [3,4,5])]
      (is (bytes/equals? (bytes/concat array1 array2)
                         (into-array Byte/TYPE [1,2,3,3,4,5]))))))

(deftest buddy-core-codecs-2
  (testing "b64 1"
    (let [mybytes (into-array Byte/TYPE (range 10))
          encoded (bytes->b64 mybytes)
          decoded (b64->bytes encoded)]
      (is (bytes/equals? decoded mybytes))))

  (testing "b64 2"
    (let [mydata  "hello world"
          encoded (-> (str->bytes mydata) (bytes->b64))
          decoded (b64->str encoded)]
      (is (= decoded mydata))))

  (testing "b64 3"
    (let [mydata  "hello world2"
          encoded (-> (str->bytes mydata) (bytes->b64 true))
          decoded (b64->str encoded false)]
      (is (= decoded mydata))))
  )
