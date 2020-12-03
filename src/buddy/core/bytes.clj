;; Copyright (c) 2015-2020 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.core.bytes
  "A collection of functions for work with byte arrays
  and bytes."
  (:refer-clojure :exclude [concat bytes?])
  (:import java.nio.ByteBuffer
           java.util.Arrays))

(def ^:private +bytes-class+
  (Class/forName "[B"))

(defn bytes?
  "Test if a first parameter is a byte
  array or not."
  [x]
  (if (nil? x)
    false
    (= +bytes-class+ (.getClass ^Object x))))

(defn fill!
  "Assigns the specified byte value to each element
  of the specified array of bytes."
  ([^bytes input val]
   (Arrays/fill input (byte val)))
  ([^bytes input val & {:keys [limit offset start end]}]
   (let [start (or offset start 0)
         end (or limit start (count input))]
     (Arrays/fill input ^int start ^int end (byte val)))))

(defn slice
  "Returns a new copy of the byte array but
  offset and crop by start and end indices."
  [^bytes input ^long start ^long end]
  (Arrays/copyOfRange input start end))

(defn copy
  "Is a specialized version of slice that
  just copy the byte array."
  [^bytes input]
  (let [length (count input)
        buffer (byte-array length)]
    (System/arraycopy input 0 buffer 0 length)
    buffer))

(defn equals?
  "Test whether two sequences of characters or bytes are equal in a way that
  protects against timing attacks. Note that this does not prevent an attacker
  from discovering the *length* of the data being compared."
  [a b]
  (let [a (map int a), b (map int b)]
    (if (and a b (= (count a) (count b)))
      (zero? (reduce bit-or 0 (map bit-xor a b)))
      false)))

(defn concat
  "Given N number of byte arrays, concat them in
  one unique byte array and return it."
  [& parts]
  (byte-array (for [ar parts
                    i ar] i)))
