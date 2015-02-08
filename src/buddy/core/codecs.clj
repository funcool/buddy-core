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

(ns buddy.core.codecs
  "Util functions for make conversion between string, bytes
  and encode them to base64 ot hex format."
  (:require [clojure.string :as str])
  (:import org.apache.commons.codec.binary.Base64
           org.apache.commons.codec.binary.Hex
           java.nio.ByteBuffer))

(defn str->bytes
  "Convert string to java bytes array"
  ([^String s]
   (str->bytes s "UTF-8"))
  ([^String s, ^String encoding]
   (.getBytes s encoding)))

(defn bytes->str
  "Convert octets to String."
  ([data]
   (bytes->str data "UTF-8"))
  ([^bytes data, ^String encoding]
   (String. data encoding)))

(defn bytes->hex
  "Convert a byte array to hex
  encoded string."
  [^bytes data]
  (Hex/encodeHexString data))

(defn hex->bytes
  "Convert hexadecimal encoded string
  to bytes array."
  [^String data]
  (Hex/decodeHex (.toCharArray data)))

(defn bytes->base64
  "Encode a bytes array to base64
and return utf8 string."
  [^bytes data]
  (Base64/encodeBase64URLSafeString data))

(defn bytes->bbase64
  "Encode a bytes array to base64 and
return bytearray."
  [^bytes data]
  (Base64/encodeBase64URLSafe data))

(defn base64->bytes
  "Decode from base64 to bytes."
  [^String s]
  (Base64/decodeBase64 s))

(defn str->base64
  "Encode to urlsafe base64."
  [^String s]
  (-> (str->bytes s)
      (Base64/encodeBase64URLSafeString)
      (str/trim)))

(defn base64->str
  "Decode from base64 to string."
  [^String s]
  (String. (base64->bytes s) "UTF8"))

(defn str->safebase64
  "Given a string, convert it to completely
  urlsafe base64 version."
  [^String s]
  (-> (str->base64 s)
      (str/replace #"\s" "")
      (str/replace "=" "")
      (str/replace "+" "-")
      (str/replace "/" "_")))

(defn bytes->safebase64
  "Given a string, convert it to completely
  urlsafe base64 version."
  [^bytes s]
  (-> (bytes->base64 s)
      (str/replace #"\s" "")
      (str/replace "=" "")
      (str/replace "+" "-")
      (str/replace "/" "_")))

(defn safebase64->str
  "Given urlsafe base64 string decode it to string."
  [^String s]
  (-> (case (mod (count s) 4)
        2 (str s "==")
        3 (str s "=")
        s)
      (str/replace "-" "+")
      (str/replace "_" "/")
      (base64->str)))

(defn safebase64->bytes
  "Given urlsafe base64 string decode it to bytes array."
  [^String s]
  (-> (case (mod (count s) 4)
        2 (str s "==")
        3 (str s "=")
        s)
      (str/replace "-" "+")
      (str/replace "_" "/")
      (base64->bytes)))

(defn long->bytes
  [^Long input]
  (let [buffer (ByteBuffer/allocate (/ Long/SIZE 8))]
    (.putLong buffer input)
    (.array buffer)))

(defn bytes->long
  [^bytes input]
  (let [buffer (ByteBuffer/allocate (/ Long/SIZE 8))]
    (.put buffer input)
    (.flip buffer)
    (.getLong buffer)))

(defprotocol ByteArray
  "Facility for convert input parameters
  to bytes array with default implementation
  for string an bytes array itself."
  (->byte-array [this] "Represent this as byte array."))

(extend-protocol ByteArray
  (Class/forName "[B")
  (->byte-array [it] it)

  String
  (->byte-array [data] (str->bytes data)))
