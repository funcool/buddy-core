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

(ns buddy.core.sign.ecdsa
  "RSASSA-PKCSv1_5 digital signature."
  (:require [buddy.core.sign.impl :as impl]
            [buddy.core.sign.proto :as proto]
            [buddy.core.sign.util :refer :all])
  (:import clojure.lang.Keyword))

(defn sign
  "Make ECDSA digital signature."
  ([input key] (sign input key :sha256))
  ([input key ^Keyword alg]
   (let [alg (concat-two-keywords :ecdsa alg)]
     (proto/make-signature input key alg))))

(defn verify
  "Verify ECDSA digital signature."
  [input ^bytes signature pkey ^Keyword alg]
  (let [alg (concat-two-keywords :ecdsa alg)]
    (proto/verify-signature input signature pkey alg)))

(def ^{:doc "Deprecated alias for sign function."
       :deprecated true}
  ecdsa sign)
