;; Copyright 2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.core.padding-tests
  (:require [clojure.test :refer :all]
            [buddy.core.codecs :as codecs]
            [buddy.core.bytes :as bytes]
            [buddy.core.padding :as padding]))

(deftest pkcs7-padding
  (let [data (byte-array 10)]
    (bytes/fill data 2)
    (padding/pad! data 6)

    (is (padding/padded? data))
    (is (= (padding/count data) 4))

    (padding/unpad! data)
    (is (= 4 (padding/count data :zerobyte)))))

(deftest tbc-padding
  (let [data (byte-array 10)]
    (bytes/fill data 2)
    (padding/pad! data 6 :tbc)

    (is (padding/padded? data :tbc))
    (is (= (padding/count data :tbc) 4))

    (padding/unpad! data :tbc)
    (is (= 4 (padding/count data :zerobyte)))))

(deftest zerobyte-padding
  (let [data (byte-array 10)]
    (bytes/fill data 2)
    (padding/pad! data 6 :zerobyte)

    (is (padding/padded? data :zerobyte))
    (is (= (padding/count data :zerobyte) 4))

    (padding/unpad! data :zerobyte)
    (is (= 4 (padding/count data :zerobyte)))))



