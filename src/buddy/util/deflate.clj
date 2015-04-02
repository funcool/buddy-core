;; Copyright (c) 2014-2015 Andrey Antukh <niwi@niwi.be>
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

;; Links to rfcs:
;; - https://tools.ietf.org/html/rfc1951

(ns buddy.util.deflate
  "Interface to DEFLATE compression algorithm."
  (:import java.io.ByteArrayInputStream
           java.io.ByteArrayOutputStream
           java.util.zip.Deflater
           java.util.zip.DeflaterOutputStream
           java.util.zip.InflaterInputStream
           java.util.zip.Inflater))

(defn compress
  "Given a plain byte array, compress it and
  return an other byte array."
  [^bytes input]
  (let [out (ByteArrayOutputStream.)
        def (Deflater. Deflater/DEFLATED true)
        dout (DeflaterOutputStream. out def)]
    (.write dout input)
    (.close dout)
    (.toByteArray out)))

(defn uncompress
  "Given a compressed data as byte-array,
  uncompress it and return as an other
  byte array."
  [^bytes input]
  (let [input (ByteArrayInputStream. bytes)
        inflater (Inflater. true)
        infout (InflaterInputStream. input inflater)
        output (ByteArrayOutputStream.)
        buffer (byte-array 1024)]
    (loop []
      (let [readed (.read infout buffer)]
        (when (pos? readed)
          (.write output buffer 0 readed)
          (recur))))
    (.close infout)
    (.close output)
    (.toByteArray output)))

