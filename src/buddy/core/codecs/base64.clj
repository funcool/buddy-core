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

(ns buddy.core.codecs.base64
  "Util functions for make conversion between string, bytes
  and encode them to base64 hex format.

  DEPRECATED: replaced by functions in `buddy.core.codecs`"
  (:require [buddy.core.codecs :as codecs])
  (:import org.apache.commons.codec.binary.Base64))

(defn encode
  "Encode data to byte array base64.
  Accepts String and byte array as argument."
  {:deprecated "1.7.1"}
  ([data]
   (encode data false))
  ([data urlsafe?]
   (let [data (codecs/to-bytes data)]
     (if urlsafe?
       (Base64/encodeBase64URLSafe ^bytes data)
       (Base64/encodeBase64 ^bytes data)))))

(defn decode
  "Decode base64 data into byte array.
  Accepts String and byte array as input
  argument."
  {:deprecated "1.7.1"}
  [data]
  (let [data (codecs/to-bytes data)]
    (Base64/decodeBase64 ^bytes data)))


