;; Copyright 2014-2020 Andrey Antukh <niwi@niwi.nz>
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
  (:import org.apache.commons.codec.binary.Hex
           java.nio.ByteBuffer
           java.util.Base64
           java.util.Base64$Encoder
           java.util.Base64$Decoder))

(defprotocol IByteArray
  "Facility for convert input parameters
  to bytes array with default implementation
  for string an bytes array itself."
  (-to-bytes [this] "Represent this as byte array."))

(defn str->bytes
  "Convert string to byte array."
  ([^String s]
   (str->bytes s "UTF-8"))
  ([^String s, ^String encoding]
   (.getBytes s encoding)))

(defn bytes->str
  "Convert byte array to String."
  ([^bytes data]
   (bytes->str data "UTF-8"))
  ([^bytes data, ^String encoding]
   (String. data encoding)))

(defn bytes->hex
  "Convert a byte array to hex encoded string."
  [^bytes data]
  (Hex/encodeHexString data))

(defn hex->bytes
  "Convert hexadecimal encoded string to bytes array."
  [^String data]
  (Hex/decodeHex (.toCharArray data)))

(defn bytes->b64
  "Encode data to base64 byte array (using standard variant)."
  [^bytes data]
  {:added "1.8.0"}
  (let [^Base64$Encoder encoder (java.util.Base64/getEncoder)]
    (.encode encoder data)))

(defn bytes->b64u
  "Encode data to base64 byte array (using url-safe variant)."
  {:added "1.8.0"}
  [^bytes data]
  (let [^Base64$Encoder encoder (-> (java.util.Base64/getUrlEncoder)
                                    (.withoutPadding))]
    (.encode encoder data)))

(defn b64->bytes
  "Decode base64 bytes array."
  {:added "1.8.0"}
  [^bytes data]
  (let [^Base64$Decoder decoder (java.util.Base64/getDecoder)]
    (.decode decoder data)))

(defn b64u->bytes
  "Decode base64 bytes array (using url-safe variant)."
  {:added "1.8.0"}
  [^bytes data]
  (let [^Base64$Decoder decoder (java.util.Base64/getUrlDecoder)]
    (.decode decoder data)))

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

(defn to-bytes
  "Encode as bytes."
  [v]
  (-to-bytes v))

(extend-protocol IByteArray
  (Class/forName "[B")
  (-to-bytes [it] it)

  nil
  (-to-bytes [_]
    (byte-array 0))

  String
  (-to-bytes [data] (str->bytes data)))
