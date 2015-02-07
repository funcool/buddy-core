;; Copyright (c) 2013-2015 Andrey Antukh <niwi@niwi.be>
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

(ns buddy.core.mac.proto
  "Hash-based Message Authentication Codes
  low level protocol definition.")

(defprotocol IMac
  "Mac engine common interface definition."
  (update [_ bytes offset length] "Update bytes in a current instance.")
  (end [_] "Return the computed mac and reset the engine."))

(defn update!
  ([engine input]
   (update engine input 0 (count input)))
  ([engine input offset]
   (update engine input offset (count input)))
  ([engine input offset length]
   (update engine input offset length)))

(defn end!
  [engine]
  (end engine))

