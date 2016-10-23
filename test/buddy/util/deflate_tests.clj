;; Copyright 2014-2016 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.util.deflate-tests
  (:require [clojure.test :as t]
            [clojure.test.check.clojure-test :refer (defspec)]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as props]
            [buddy.core.bytes :as bytes]
            [buddy.util.deflate :as df]))

(defspec deflate-compress-uncompress-spec 1000
  (props/for-all
   [data gen/bytes]
   (let [result1 (df/compress data)
         result2 (df/uncompress result1)]
     (t/is (bytes/equals? data result2)))))

(defspec deflate-compress-uncompress-zlib-spec 1000
         (props/for-all
           [data gen/bytes]
           (let [result1 (df/compress data {:nowrap false})
                 result2 (df/uncompress result1 {:nowrap false})]
             (t/is (bytes/equals? data result2)))))

(defspec deflate-compress-uncompress-zlib-fallback-spec 1000
         (props/for-all
           [data gen/bytes]
           (let [result1 (df/compress data {:nowrap false})
                 result2 (df/uncompress result1)]
             (t/is (bytes/equals? data result2)))))