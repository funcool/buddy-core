;; Copyright (c) 2018 Andrey Antukh <niwi@niwi.nz>
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

(ns buddy.util.ecdsa
  "ECDSA related DER encoding decoding helpers."
  (:import buddy.util.ECDSA))

(defn transcode-to-der
  [^bytes data]
  (ECDSA/transcodeSignatureToDER data))

(defn transcode-to-concat
  [^bytes data length]
  (ECDSA/transcodeSignatureToConcat data ^int length))
